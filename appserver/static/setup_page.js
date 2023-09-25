require([
    'jquery',
    'splunkjs/mvc/simplexml/ready!'
], function($) {

    var ck_div = $(".ck_div_input_fields");

    $.ajax({
        type: "GET",
        url: "../../../../en-US/splunkd/__raw/services/iphub/iphubsetup/iphub?output_mode=json",
        success: function(setup_parameters) {

            var credentialKeyString = setup_parameters['entry'][0]['content']['credential_key'];
            var credentialString = setup_parameters['entry'][0]['content']['credential'];
            var useKVStoreString = setup_parameters['entry'][0]['content']['useKVStore'];
            var debugLoggingString = setup_parameters['entry'][0]['content']['debugLogging'];
            var proxySettingsString = setup_parameters['entry'][0]['content']['proxy_settings'];

            var ck_api_key = $("#iphub_api_key");
            ck_api_key.val(credentialString);

            var proxy_settings = $("#proxy_settings");
            proxy_settings.val(proxySettingsString);


            if (useKVStoreString == "1") {
                $("input[name='iphub_use_kvstore']").prop('checked', true);
            }
            
            if (debugLoggingString == "1") {
                $("input[name='iphub_debug_logging']").prop('checked', true);
            }

        },
        error: function() {


        }
    });

    var submit_button = $("#ck_submit_button");
    var cancel_button = $("#ck_cancel_button");


    $(submit_button).click(function(e) {
        e.preventDefault();

        var credential_key_string = ""
        var credential_string = ""
        var proxy_settings_string = ""


        credential_key_string = $("#iphub_api_key").val();
        proxy_settings_string = $("#proxy_settings").val();

        if ($("input[name='iphub_use_kvstore']").prop('checked')) {
            useKVStore = "1";
        } else {
            useKVStore = "0";
        }
        if ($("input[name='iphub_debug_logging']").prop('checked')) {
            debugLogging = "1";
        } else {
            debugLogging = "0";
        }

        $.ajax({
            type: "POST",
            url: "../../../../en-US/splunkd/__raw/services/iphub/iphubsetup/iphub",
            data: "credential_key=iphub_api_key&credential=" + credential_key_string + "&useKVStore=" + useKVStore + "&debugLogging=" + debugLogging + "&proxy_settings=" + proxy_settings_string, 
            success: function(text) {
                window.location.href = '../TA-iphub/search';
            },
            error: function() {
            }
        });

        $('div[name^="ck_input"]').remove();
        $(".ck_div_input_fields").append('<div name="saving_creds_msg" style="text-align: center;"><p class="helpText"><h3>Encrypting and Saving Credentials</h3><h3>Plus reloading app config which can take some time. Be patient this page will finish eventually.</h3></p></div>');

    });

    $(cancel_button).click(function(e) {
        e.preventDefault();
        $('div[name^="ck_input"]').remove();
        window.location.href = '../TA-iphub/search';

    });




});