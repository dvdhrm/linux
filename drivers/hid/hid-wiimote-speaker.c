/*
 * Driver for audio speakers of Nintendo Wii / Wii U peripherals
 * Copyright (c) 2012-2013 David Herrmann <dh.herrmann@gmail.com>
 *
 * Yamaha ADPCM encoder based on ffmpeg project:
 * Copyright (c) 2001-2003 The ffmpeg Project
 */

/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

/*
 * Audio Speakers
 * Some Wii peripherals provide an audio speaker that supports 8bit PCM, 4bit
 * Yamaha ADPCM and some other mostly unknown formats. Not all setup options
 * are known, but we know how to setup an 8bit PCM or 4bit ADPCM stream and
 * adjust volume. Data is sent as 20bytes chunks and needs to be streamed at
 * a constant rate.
 */

#include <linux/device.h>
#include <linux/hid.h>
#include <linux/hrtimer.h>
#include <linux/interrupt.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <sound/control.h>
#include <sound/core.h>
#include <sound/initval.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include "hid-wiimote.h"

/*
 * Yamaha ADPCM encoder
 * The Wii Remote implements a codec which was identified to be Yamaha ADPCM.
 * This implementation is based on the ffmpeg project copyrighted by:
 *   Copyright (c) 2001-2003 The ffmpeg Project
 * We are not entirely sure whether the remote implements the codec in the
 * exact same way and we get some spurious volume shifts. But these might be
 * caused by other things than a wrong codec.
 * Nevertheless, it works quite well and produces much better results than
 * direct 8bit PCM streams.
 */

struct yadpcm {
	__s32 step;
	__s32 prev;
};

static const __s8 yadpcm_diff[16] = {
	 1,  3,  5,  7,  9,  11,  13,  15,
	-1, -3, -5, -7, -9, -11, -13, -15,
};

static const __s16 yadpcm_step[16] = {
	230, 230, 230, 230, 307, 409, 512, 614,
	230, 230, 230, 230, 307, 409, 512, 614,
};

/* Reset yadpcm state to initial state. Don't call this during a stream
 * transmission as this will corrupt the remote decoder and produce unwanted
 * results. */
static void yadpcm_reset(struct yadpcm *yadpcm)
{
	yadpcm->step = 127;
	yadpcm->prev = 0;
}

/* Encode the signed 16bit PCM value @in based on the current yadpcm state
 * @yadpcm and return it. This will return a 4bit value (0-15). The upper
 * 4bits will be 0 and must be discarded. */
static __u8 yadpcm_encode(struct yadpcm *yadpcm, __s16 in)
{
	__s32 diff;
	__u8 val;

	diff = (__s32)in - yadpcm->prev;
	val = min_t(__s32, 7, abs(diff) * 4 / yadpcm->step);
	if (diff < 0)
		val += 8;

	yadpcm->prev += (yadpcm->step * yadpcm_diff[val]) / 8;
	yadpcm->prev = clamp_t(__s32, yadpcm->prev, -0x8000, 0x7fff);

	yadpcm->step = (yadpcm->step * yadpcm_step[val]) >> 8;
	yadpcm->step = clamp_t(__s32, yadpcm->step, 127, 24567);

	return val;
}

/* wiimod speaker */

struct wiimote_speaker {
	spinlock_t lock;
	struct snd_card *card;
	struct wiimote_data *wdata;
	unsigned int online : 1;
	unsigned int running : 1;
	unsigned int adpcm : 1;
	unsigned int le : 1;
	unsigned int mute : 1;
	__u8 volume;

	unsigned long pos;
	__u64 interval;
	struct yadpcm yadpcm;
	struct snd_pcm_substream *subs;
	struct mutex runlock;

	struct hrtimer timer;
	struct tasklet_struct tasklet;
};

static int wiimod_speaker_enable(struct wiimote_speaker *speaker)
{
	struct wiimote_data *wdata = speaker->wdata;
	unsigned long flags;

	spin_lock_irqsave(&wdata->state.lock, flags);

	if (!speaker->online) {
		speaker->online = 1;
		speaker->running = 0;
		wiiproto_req_speaker(wdata, true);
		wiiproto_req_mute(wdata, speaker->mute);
	}

	spin_unlock_irqrestore(&wdata->state.lock, flags);

	return 0;
}

static void wiimod_speaker_disable(struct wiimote_speaker *speaker)
{
	struct wiimote_data *wdata = speaker->wdata;
	unsigned long flags;

	spin_lock_irqsave(&wdata->state.lock, flags);

	if (speaker->online) {
		speaker->running = 0;
		speaker->online = 0;
		wiiproto_req_speaker(wdata, false);
	}

	spin_unlock_irqrestore(&wdata->state.lock, flags);
}

static void wiimod_speaker_set_mute(struct wiimote_speaker *speaker, bool mute)
{
	struct wiimote_data *wdata = speaker->wdata;
	unsigned long flags;

	spin_lock_irqsave(&wdata->state.lock, flags);

	if (speaker->mute != mute) {
		speaker->mute = mute;
		if (speaker->online)
			wiiproto_req_mute(wdata, mute);
	}

	spin_unlock_irqrestore(&wdata->state.lock, flags);
}

static void wiimod_speaker_set_volume(struct wiimote_speaker *speaker,
				      __u8 volume)
{
	struct wiimote_data *wdata = speaker->wdata;
	unsigned long flags;

	spin_lock_irqsave(&wdata->state.lock, flags);

	if (speaker->volume != volume) {
		speaker->volume = volume;
		if (speaker->online) {
			if (speaker->adpcm)
				volume >>= 2;
			wiiproto_req_wmem(wdata, false, 0xa20005, &volume,
					  sizeof(volume));
		}
	}

	spin_unlock_irqrestore(&wdata->state.lock, flags);
}

static int wiimod_speaker_setup(struct wiimote_speaker *speaker, bool adpcm,
				__u16 rate)
{
	struct wiimote_data *wdata = speaker->wdata;
	unsigned long flags;
	__u8 config[7], wmem;
	__u16 r;
	int ret;

	if (!rate)
		return -EINVAL;

	r = 12000000ULL / rate;
	config[0] = 0x00;
	config[1] = adpcm ? 0x00 : 0x40;
	config[2] = r & 0x00ff;
	config[3] = (r & 0xff00) >> 8;
	config[4] = 0x00;
	config[5] = 0x00;
	config[6] = 0x00;

	wiimote_cmd_acquire_noint(wdata);

	/* mute speaker during setup and read/write volume field */
	spin_lock_irqsave(&wdata->state.lock, flags);

	wiiproto_req_mute(wdata, true);
	config[4] = speaker->volume;
	if (adpcm)
		config[4] >>= 2;

	spin_unlock_irqrestore(&wdata->state.lock, flags);

	/* power speaker */
	wmem = 0x01;
	ret = wiimote_cmd_write(wdata, 0xa20009, &wmem, sizeof(wmem));
	if (ret)
		goto out_unlock;

	/* prepare setup */
	wmem = 0x08;
	ret = wiimote_cmd_write(wdata, 0xa20001, &wmem, sizeof(wmem));
	if (ret)
		goto out_unlock;

	/* write configuration */
	ret = wiimote_cmd_write(wdata, 0xa20001, config, sizeof(config));
	if (ret)
		goto out_unlock;

	/* enable speaker */
	wmem = 0x01;
	ret = wiimote_cmd_write(wdata, 0xa20008, &wmem, sizeof(wmem));
	if (ret)
		goto out_unlock;

out_unlock:
	wiimote_cmd_release(wdata);
	return ret;
}

/* returns true if a period has elapsed */
static bool wiimod_speaker_push(struct wiimote_speaker *speaker)
{
	struct wiimote_data *wdata = speaker->wdata;
	struct snd_pcm_runtime *runtime = speaker->subs->runtime;
	unsigned long flags;
	bool elapsed;
	unsigned long buflen, plen, len, i;
	__u8 *src, buf[22], enc;
	__s16 val;

	buflen = frames_to_bytes(runtime, runtime->buffer_size);
	plen = frames_to_bytes(runtime, runtime->period_size);
	src = runtime->dma_area;

	len = buflen - speaker->pos;

	if (speaker->adpcm) {
		for (i = 0; i < 40; ++i) {
			val = *(__s16*)&src[speaker->pos];
			speaker->pos += 2;
			if (speaker->pos >= buflen)
				speaker->pos = 0;
			if (speaker->le)
				le16_to_cpus(&val);
			else
				be16_to_cpus(&val);

			enc = yadpcm_encode(&speaker->yadpcm, val);
			if (i & 0x1)
				buf[2 + (i / 2)] |= enc;
			else
				buf[2 + (i / 2)] = enc << 4;
		}
		elapsed = (speaker->pos % plen) < 80;
	} else {
		if (len < 20) {
			memcpy(&buf[2], &src[speaker->pos], len);
			memcpy(&buf[len + 2], src, 20 - len);
		} else {
			memcpy(&buf[2], &src[speaker->pos], 20);
		}

		speaker->pos += 20;
		speaker->pos %= buflen;
		elapsed = (speaker->pos % plen) < 20;
	}

	spin_lock_irqsave(&wdata->state.lock, flags);
	wiiproto_req_audio(wdata, buf, 20);
	spin_unlock_irqrestore(&wdata->state.lock, flags);

	return elapsed;
}

/* timer handling */

static void wiimod_speaker_task(unsigned long data)
{
	struct wiimote_speaker *speaker = (void*)data;
	unsigned long flags;
	bool elapsed = false;

	spin_lock_irqsave(&speaker->lock, flags);
	if (speaker->wdata && speaker->running)
		elapsed = wiimod_speaker_push(speaker);
	spin_unlock_irqrestore(&speaker->lock, flags);

	if (elapsed)
		snd_pcm_period_elapsed(speaker->subs);
}

static enum hrtimer_restart wiimod_speaker_tick(struct hrtimer *timer)
{
	struct wiimote_speaker *speaker = container_of(timer,
						       struct wiimote_speaker,
						       timer);
	unsigned long missed;

	tasklet_schedule(&speaker->tasklet);

	missed = hrtimer_forward_now(timer, ns_to_ktime(speaker->interval));
	if (missed > 1)
		snd_printdd("wiimote: speaker: missed %lu timer interrupts\n",
			    missed - 1);

	return HRTIMER_RESTART;
}

/* PCM layer */

static const struct snd_pcm_hardware wiimod_speaker_playback_hw = {
	.info = SNDRV_PCM_INFO_MMAP |
		SNDRV_PCM_INFO_MMAP_VALID |
		SNDRV_PCM_INFO_INTERLEAVED,
	.formats = SNDRV_PCM_FMTBIT_S8 | SNDRV_PCM_FMTBIT_S16_LE |
		   SNDRV_PCM_FMTBIT_S16_BE,
	.rates = SNDRV_PCM_RATE_CONTINUOUS,
	.rate_min = 500,
	.rate_max = 2000,
	.channels_min = 1,
	.channels_max = 1,
	.buffer_bytes_max = 32768,
	.period_bytes_min = 512,
	.period_bytes_max = 32768,
	.periods_min = 1,
	.periods_max = 1024,
};

static int wiimod_speaker_playback_open(struct snd_pcm_substream *substream)
{
	struct wiimote_speaker *speaker = snd_pcm_substream_chip(substream);
	struct snd_pcm_runtime *runtime = substream->runtime;
	unsigned long flags;
	int ret;

	runtime->hw = wiimod_speaker_playback_hw;

	spin_lock_irqsave(&speaker->lock, flags);
	ret = -ENODEV;
	if (speaker->wdata) {
		runtime->private_data = speaker->wdata;
		ret = wiimod_speaker_enable(speaker);
	}
	spin_unlock_irqrestore(&speaker->lock, flags);

	return ret;
}

static int wiimod_speaker_playback_close(struct snd_pcm_substream *substream)
{
	struct wiimote_speaker *speaker = snd_pcm_substream_chip(substream);
	unsigned long flags;

	spin_lock_irqsave(&speaker->lock, flags);
	if (speaker->wdata)
		wiimod_speaker_disable(speaker);
	speaker->running = 0;
	speaker->online = 0;
	spin_unlock_irqrestore(&speaker->lock, flags);

	hrtimer_cancel(&speaker->timer);
	tasklet_kill(&speaker->tasklet);

	return 0;
}

static int wiimod_speaker_playback_hw_params(struct snd_pcm_substream *subs,
					     struct snd_pcm_hw_params *hw)
{
	return snd_pcm_lib_alloc_vmalloc_buffer(subs, params_buffer_bytes(hw));
}

static int wiimod_speaker_playback_hw_free(struct snd_pcm_substream *subs)
{
	return snd_pcm_lib_free_vmalloc_buffer(subs);
}

static int wiimod_speaker_playback_prepare(struct snd_pcm_substream *subs)
{
	struct wiimote_speaker *speaker = snd_pcm_substream_chip(subs);
	struct wiimote_data *wdata;
	struct snd_pcm_runtime *runtime = subs->runtime;
	int ret, online;
	unsigned long flags;

	/* runlock synchronizes with device hotplugging */
	mutex_lock(&speaker->runlock);

	spin_lock_irqsave(&speaker->lock, flags);
	wdata = speaker->wdata;
	online = speaker->online;
	speaker->running = 0;
	spin_unlock_irqrestore(&speaker->lock, flags);

	if (!wdata || !online) {
		ret = -ENODEV;
		goto unlock;
	}

	hrtimer_cancel(&speaker->timer);
	tasklet_kill(&speaker->tasklet);

	spin_lock_irqsave(&speaker->lock, flags);
	speaker->pos = 0;
	speaker->subs = subs;
	speaker->adpcm = (runtime->format != SNDRV_PCM_FORMAT_S8);
	speaker->le = (runtime->format == SNDRV_PCM_FORMAT_S16_LE);
	speaker->interval = 40U * 1000000000ULL / runtime->rate;
	if (!speaker->adpcm)
		speaker->interval >>= 1;
	yadpcm_reset(&speaker->yadpcm);
	spin_unlock_irqrestore(&speaker->lock, flags);

	/* Perform speaker setup. This may take a few milliseconds and the
	 * handlers perform synchronous network operations so this
	 * may sleep. */
	switch (runtime->format) {
	case SNDRV_PCM_FORMAT_S8:
	case SNDRV_PCM_FORMAT_S16_LE:
	case SNDRV_PCM_FORMAT_S16_BE:
		ret = wiimod_speaker_setup(speaker, speaker->adpcm,
					   runtime->rate);
		break;
	default:
		ret = -EINVAL;
	}

unlock:
	mutex_unlock(&speaker->runlock);
	return ret;
}

static int wiimod_speaker_playback_trigger(struct snd_pcm_substream *subs,
					   int cmd)
{
	struct wiimote_speaker *speaker = snd_pcm_substream_chip(subs);
	struct wiimote_data *wdata;
	unsigned long flags;

	spin_lock_irqsave(&speaker->lock, flags);

	wdata = speaker->wdata;
	if (!wdata || !speaker->online)
		goto unlock;

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_RESUME:
	case SNDRV_PCM_TRIGGER_START:
		/* unmute device on start if not muted by user-space */
		spin_lock(&wdata->state.lock);
		if (!speaker->mute)
			wiiproto_req_mute(wdata, false);
		spin_unlock(&wdata->state.lock);

		hrtimer_start(&speaker->timer, ktime_set(0, speaker->interval),
			      HRTIMER_MODE_REL);
		speaker->running = 1;
		break;
	case SNDRV_PCM_TRIGGER_SUSPEND:
	case SNDRV_PCM_TRIGGER_STOP:
		/* mute device when stopping transmission */
		spin_lock(&wdata->state.lock);
		wiiproto_req_mute(wdata, true);
		spin_unlock(&wdata->state.lock);

		speaker->running = 0;
		hrtimer_cancel(&speaker->timer);
		break;
	}

unlock:
	spin_unlock_irqrestore(&speaker->lock, flags);
	return 0;
}

static snd_pcm_uframes_t wiimod_speaker_playback_pointer(struct snd_pcm_substream *subs)
{
	struct wiimote_speaker *speaker = snd_pcm_substream_chip(subs);

	return bytes_to_frames(subs->runtime, speaker->pos);
}

static struct snd_pcm_ops wiimod_speaker_playback_ops = {
	.open		= wiimod_speaker_playback_open,
	.close		= wiimod_speaker_playback_close,
	.ioctl		= snd_pcm_lib_ioctl,
	.hw_params	= wiimod_speaker_playback_hw_params,
	.hw_free	= wiimod_speaker_playback_hw_free,
	.prepare	= wiimod_speaker_playback_prepare,
	.trigger	= wiimod_speaker_playback_trigger,
	.pointer	= wiimod_speaker_playback_pointer,
	.page		= snd_pcm_lib_get_vmalloc_page,
	.mmap		= snd_pcm_lib_mmap_vmalloc,
};

/* volume control */

static int wiimod_speaker_volume_info(struct snd_kcontrol *kcontrol,
				      struct snd_ctl_elem_info *info)
{
	info->type = SNDRV_CTL_ELEM_TYPE_INTEGER;
	info->count = 1;
	info->value.integer.min = 0;
	info->value.integer.max = 0xff;

	return 0;
}

static int wiimod_speaker_volume_get(struct snd_kcontrol *kcontrol,
				     struct snd_ctl_elem_value *val)
{
	struct wiimote_speaker *speaker = snd_kcontrol_chip(kcontrol);

	val->value.integer.value[0] = speaker->volume;

	return 0;
}

static int wiimod_speaker_volume_put(struct snd_kcontrol *kcontrol,
				     struct snd_ctl_elem_value *val)
{
	struct wiimote_speaker *speaker = snd_kcontrol_chip(kcontrol);
	unsigned long value, flags;

	value = val->value.integer.value[0];
	if (value > 0xff)
		value = 0xff;

	spin_lock_irqsave(&speaker->lock, flags);
	if (speaker->wdata)
		wiimod_speaker_set_volume(speaker, value);
	spin_unlock_irqrestore(&speaker->lock, flags);

	return 0;
}

static const struct snd_kcontrol_new wiimod_speaker_volume = {
	.iface = SNDRV_CTL_ELEM_IFACE_MIXER,
	.name = "PCM Playback Volume",
	.access = SNDRV_CTL_ELEM_ACCESS_READWRITE,
	.info = wiimod_speaker_volume_info,
	.get = wiimod_speaker_volume_get,
	.put = wiimod_speaker_volume_put,
};

/* mute control */

static int wiimod_speaker_mute_get(struct snd_kcontrol *kcontrol,
				   struct snd_ctl_elem_value *val)
{
	struct wiimote_speaker *speaker = snd_kcontrol_chip(kcontrol);

	val->value.integer.value[0] = !speaker->mute;

	return 0;
}

static int wiimod_speaker_mute_put(struct snd_kcontrol *kcontrol,
				   struct snd_ctl_elem_value *val)
{
	struct wiimote_speaker *speaker = snd_kcontrol_chip(kcontrol);
	unsigned long flags;

	spin_lock_irqsave(&speaker->lock, flags);
	if (speaker->wdata)
		wiimod_speaker_set_mute(speaker,
					!val->value.integer.value[0]);
	spin_unlock_irqrestore(&speaker->lock, flags);

	return 0;
}

static const struct snd_kcontrol_new wiimod_speaker_mute = {
	.iface = SNDRV_CTL_ELEM_IFACE_MIXER,
	.name = "PCM Playback Switch",
	.access = SNDRV_CTL_ELEM_ACCESS_READWRITE,
	.info = snd_ctl_boolean_mono_info,
	.get = wiimod_speaker_mute_get,
	.put = wiimod_speaker_mute_put,
};

/* initialization and setup */

static int wiimod_speaker_probe(const struct wiimod_ops *ops,
				struct wiimote_data *wdata)
{
	int ret;
	struct wiimote_speaker *speaker;
	struct snd_card *card;
	struct snd_kcontrol *kcontrol;
	struct snd_pcm *pcm;

	/* create sound card device */
	ret = snd_card_create(-1, NULL, THIS_MODULE,
			      sizeof(struct wiimote_speaker), &card);
	if (ret)
		return ret;
	speaker = card->private_data;

	wdata->speaker = speaker;
	speaker->wdata = wdata;
	speaker->card = card;
	speaker->mute = 1;
	speaker->volume = 0xff;
	strcpy(card->driver, "hid-wiimote");
	strcpy(card->shortname, "wiimote");
	strcpy(card->longname, "Nintendo Wii Remote speaker");

	yadpcm_reset(&speaker->yadpcm);
	spin_lock_init(&speaker->lock);
	mutex_init(&speaker->runlock);
	hrtimer_init(&speaker->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	speaker->timer.function = wiimod_speaker_tick;
	tasklet_init(&speaker->tasklet, wiimod_speaker_task,
		     (unsigned long)speaker);

	/* create volume control */
	kcontrol = snd_ctl_new1(&wiimod_speaker_volume, speaker);
	if (!kcontrol) {
		ret = -ENOMEM;
		goto err_free;
	}

	ret = snd_ctl_add(card, kcontrol);
	if (ret) {
		snd_ctl_free_one(kcontrol);
		goto err_free;
	}

	/* create mute control */
	kcontrol = snd_ctl_new1(&wiimod_speaker_mute, speaker);
	if (!kcontrol) {
		ret = -ENOMEM;
		goto err_free;
	}

	ret = snd_ctl_add(card, kcontrol);
	if (ret) {
		snd_ctl_free_one(kcontrol);
		goto err_free;
	}

	/* create PCM sub-device for playback */
	ret = snd_pcm_new(card, "Speaker", 0, 1, 0, &pcm);
	if (ret)
		goto err_free;

	pcm->private_data = speaker;
	snd_pcm_set_ops(pcm, SNDRV_PCM_STREAM_PLAYBACK,
			&wiimod_speaker_playback_ops);

	/* register sound card */
	snd_card_set_dev(card, &wdata->hdev->dev);
	ret = snd_card_register(card);
	if (ret)
		goto err_free;

	return 0;

err_free:
	snd_card_free(card);
	wdata->speaker = NULL;
	return ret;
}

static void wiimod_speaker_remove(const struct wiimod_ops *ops,
				  struct wiimote_data *wdata)
{
	struct wiimote_speaker *speaker = wdata->speaker;
	unsigned long flags;

	if (!speaker)
		return;

	mutex_lock(&speaker->runlock);
	spin_lock_irqsave(&speaker->lock, flags);

	wdata->speaker = NULL;
	speaker->online = 0;
	speaker->wdata = NULL;

	spin_lock(&wdata->state.lock);
	wiiproto_req_mute(wdata, true);
	wiiproto_req_speaker(wdata, false);
	spin_unlock(&wdata->state.lock);

	spin_unlock_irqrestore(&speaker->lock, flags);
	mutex_unlock(&speaker->runlock);

	hrtimer_cancel(&speaker->timer);
	tasklet_kill(&speaker->tasklet);
	snd_card_free_when_closed(speaker->card);
}

const struct wiimod_ops wiimod_speaker = {
	.flags = 0,
	.arg = 0,
	.probe = wiimod_speaker_probe,
	.remove = wiimod_speaker_remove,
};
