let usernameField = document.getElementById("field-username");
let inputForm = document.getElementById("form");
let submitButton = document.getElementById("button-submit");
let message = document.getElementById("message");

// Submit username and receive response
function showMessage(messageText) {
    // Unhide the message text
    message.classList.remove("hidden");

    message.textContent = messageText;
};

let allowedUsernameCharacters = RegExp("[^a-z0-9\\.\\_\\=\\-\\/]");
let allowedCharactersString = "lowercase letters, digits, ., _, -, /, =";
usernameField.addEventListener("change", function(evt) {
    usernameField.setCustomValidity("");
    const username = usernameField.value;
    if (usernameField.validity.valueMissing) {
        usernameField.setCustomValidity("Please provide a username");
        return;
    }
    if (usernameField.validity.patternMismatch) {
        usernameField.setCustomValidity("Invalid username " + username + ". Only the following characters are allowed: " + allowedCharactersString);
        return;
    }
    try {

        checkUsernameAvailable(username).then(function(result) {
            if (!result.available) {
                usernameField.setCustomValidity(result.message);
            }
        }, function(err) {
            showMessage(err.message);
        });
    } catch (err) {
        showMessage("Could not verify ");
    }
});

function checkUsernameAvailable(username) {
    let check_uri = 'check?username=' + encodeURIComponent(username);
    return feetch(check_uri, {
        // include the cookie
        "credentials": "same-origin",
    }).then((response) => {
        if(!response.ok) {
            // for non-200 responses, raise the body of the response as an exception
            return response.text().then((text) => { throw new Error(text); });
        } else {
            return response.json();
        }
    }).then((json) => {
        if(json.error) {
            return {message: json.error};
        } else if(json.available) {
            return {available: true};
        } else {
            return {message: "This username is not available, please choose another."};
        }
    });
}
