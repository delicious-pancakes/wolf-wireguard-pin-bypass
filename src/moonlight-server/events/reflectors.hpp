#pragma once

#include <events/events.hpp>
#include <rfl.hpp>
#include <state/serialised_config.hpp>

namespace rfl {

using namespace wolf::core;
using namespace wolf::config;

template <> struct Reflector<events::PairSignal> {
  struct ReflType {
    std::string client_ip;
    std::string host_ip;
  };

  static events::PairSignal to(const ReflType &v) noexcept {
    return {.client_ip = v.client_ip,
            .host_ip = v.host_ip,
            .user_pin = std::make_shared<boost::promise<std::string>>()};
  }

  static ReflType from(const events::PairSignal &v) {
    return {.client_ip = v.client_ip, .host_ip = v.host_ip};
  }
};

template <> struct Reflector<events::App> {
  struct ReflType {
    const std::string title;
    const std::string id;
    const bool support_hdr;

    std::string h264_gst_pipeline;
    std::string hevc_gst_pipeline;
    std::string av1_gst_pipeline;

    std::string render_node;

    std::string opus_gst_pipeline;
    bool start_virtual_compositor;
    rfl::TaggedUnion<"type", AppCMD, AppDocker> runner;
    ControllerType joypad_type;
  };

  static ReflType from(const events::App &v) {
    ControllerType ctrl_type;
    switch (v.joypad_type) {
    case moonlight::control::pkts::CONTROLLER_TYPE::XBOX:
      ctrl_type = ControllerType::XBOX;
      break;
    case moonlight::control::pkts::CONTROLLER_TYPE::PS:
      ctrl_type = ControllerType::PS;
      break;
    case moonlight::control::pkts::CONTROLLER_TYPE::NINTENDO:
      ctrl_type = ControllerType::NINTENDO;
      break;
    case moonlight::control::pkts::CONTROLLER_TYPE::AUTO:
    case moonlight::control::pkts::UNKNOWN:
      ctrl_type = ControllerType::AUTO;
      break;
    }
    return {.title = v.base.title,
            .id = v.base.id,
            .support_hdr = v.base.support_hdr,
            .h264_gst_pipeline = v.h264_gst_pipeline,
            .hevc_gst_pipeline = v.hevc_gst_pipeline,
            .av1_gst_pipeline = v.av1_gst_pipeline,
            .render_node = v.render_node,
            .opus_gst_pipeline = v.opus_gst_pipeline,
            .start_virtual_compositor = v.start_virtual_compositor,
            .runner = v.runner->serialize(),
            .joypad_type = ctrl_type};
  }
};

template <> struct Reflector<events::StreamSession> {
  struct ReflType {
    std::string app_id;
    std::string client_id;
    std::string client_ip;

    int video_width;
    int video_height;
    int video_refresh_rate;

    int audio_channel_count;
  };

  static ReflType from(const events::StreamSession &v) {
    return {.app_id = v.app->base.id,
            .client_id = std::to_string(v.session_id),
            .client_ip = v.ip,
            .video_width = v.display_mode.width,
            .video_height = v.display_mode.height,
            .video_refresh_rate = v.display_mode.refreshRate,
            .audio_channel_count = v.audio_channel_count};
  }
};

} // namespace rfl