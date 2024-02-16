package com.ceco.nougat.gravitybox.tuner;

import com.ceco.nougat.gravitybox.managers.TunerManager;

import java.util.Arrays;
import java.util.List;

public class TunerBlacklist {

    private static final List<String> sFramework = Arrays.asList(
            "action_bar_embed_tabs",
            "action_bar_expanded_action_views_exclusive",
            "config_allowEscrowTokenForTrustAgent",
            "config_annoy_dianne",
            "config_auto_attach_data_on_creation",
            "config_cdma_3waycall_flash_delay",
            "config_datause_notification_type",
            "config_enableFusedLocationOverlay",
            "config_enableGeocoderOverlay",
            "config_enableGeofenceOverlay",
            "config_enableHardwareFlpOverlay",
            "config_enableNetworkLocationOverlay",
            "config_networkPolicyDefaultWarning",
            "config_networkSamplingWakesDevice",
            "config_sf_slowBlur",
            "config_valid_wappush_index",
            "date_picker_mode",
            "default_data_warning_level_mb",
            "dock_enter_exit_duration",
            "enable_pbap_pce_profile",
            "preferences_prefer_dual_pane",
            "split_action_bar_is_narrow",
            "target_honeycomb_needs_options_menu",
            "thumbnail_width_tv",
            "time_picker_mode",
            "use_lock_pattern_drawable"
    );

    private static final List<String> sSystemUi = Arrays.asList(
            "abc_action_bar_embed_tabs",
            "abc_allow_stacked_button_bar",
            "abc_config_actionMenuItemAllCaps",
            "abc_config_activityDefaultDur",
            "abc_config_activityShortDur",
            "abc_config_closeDialogWhenTouchOutside",
            "abc_config_showMenuShortcutsWhenKeyboardPresent",
            "cancel_button_image_alpha",
            "car_user_switcher_anim_update_ms",
            "car_user_switcher_timeout_ms",
            "config_activityDefaultDur",
            "config_enableLockScreenRotation",
            "config_enableLockScreenTranslucentDecor",
            "config_enablePersistentDockedActivity",
            "config_search_panel_view_vibration_duration",
            "config_tooltipAnimTime",
            "config_vibration_duration",
            "kg_selector_gravity",
            "kg_sim_puk_account_full_screen",
            "lb_browse_headers_transition_delay",
            "lb_browse_headers_transition_duration",
            "lb_browse_rows_anim_duration",
            "lb_card_activated_animation_duration",
            "lb_card_selected_animation_delay",
            "lb_card_selected_animation_duration",
            "lb_details_description_body_max_lines",
            "lb_details_description_body_min_lines",
            "lb_details_description_subtitle_max_lines",
            "lb_details_description_title_max_lines",
            "lb_error_message_max_lines",
            "lb_guidedactions_item_animation_duration",
            "lb_guidedactions_item_description_min_lines",
            "lb_guidedactions_item_title_max_lines",
            "lb_guidedactions_item_title_min_lines",
            "lb_guidedstep_activity_background_fade_duration_ms",
            "lb_onboarding_header_description_delay",
            "lb_onboarding_header_title_delay",
            "lb_playback_bg_fade_in_ms",
            "lb_playback_bg_fade_out_ms",
            "lb_playback_controls_fade_in_ms",
            "lb_playback_controls_fade_out_ms",
            "lb_playback_controls_show_time_ms",
            "lb_playback_description_fade_in_ms",
            "lb_playback_description_fade_out_ms",
            "lb_playback_rows_fade_delay_ms",
            "lb_playback_rows_fade_in_ms",
            "lb_playback_rows_fade_out_ms",
            "lb_search_bar_speech_mode_background_alpha",
            "lb_search_bar_text_mode_background_alpha",
            "lb_search_orb_pulse_duration_ms",
            "lb_search_orb_scale_duration_ms",
            "mr_controller_volume_group_list_animation_duration_ms",
            "mr_controller_volume_group_list_fade_in_duration_ms",
            "mr_controller_volume_group_list_fade_out_duration_ms",
            "slideEdgeEnd",
            "slideEdgeStart",
            "allow_stacked_button_bar",
            "app_bar_elevation_anim_duration",
            "bottom_sheet_slide_duration",
            "button_pressed_animation_delay",
            "button_pressed_animation_duration",
            "config_activityShortDur",
            "config_closeDialogWhenTouchOutside",
            "config_read_icons_from_xml",
            "op_date_picker_mode",
            "preference_fragment_scrollbarStyle",
            "preference_screen_header_scrollbarStyle",
            "preferences_left_pane_weight",
            "preferences_prefer_dual_pane",
            "preferences_right_pane_weight"
    );

    public static boolean isBlacklisted(TunerManager.Category category, String key) {
        switch (category) {
            case FRAMEWORK: return sFramework.contains(key);
            case SYSTEMUI: return sSystemUi.contains(key);
            default: return false;
        }
    }
}
