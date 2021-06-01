<script>
    let handle;
    let email;
    let password;
    let password_confirm;

    let err_message = "";

    function onSubmit(e) {
        e.preventDefault();

        if (password !== password_confirm) {
            return;
        }

        let request = {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                handle: handle,
                email: email,
                password: password,
            }),
        };

        fetch("http://localhost:8080/register", request).then(async function (
            response
        ) {
            let data = await response.json();
            console.log(data);
        });
    }
</script>

<form on:submit={onSubmit}>
    <h3>Register</h3>
    <p>
        <label for="handle">Account Handle</label>
        <input id="handle" type="text" placeholder="" bind:value={handle} />
    </p>
    <p>
        <label for="email">Account Email</label>
        <input id="email" type="text" placeholder="" bind:value={email} />
    </p>
    <p>
        <label for="password">Password</label>
        <input id="password" type="password" bind:value={password} />
    </p>
    <p>
        <label for="confirm_password">Confirm Password</label>
        <input
            id="confirm_password"
            type="password"
            bind:value={password_confirm}
        />
    </p>
    <p>
        <input type="submit" value="Register Account" />
    </p>
    {#if password != password_confirm}
        <p>Password and Confirm Password are not the same</p>
    {/if}
    {#if err_message != ""}
        <p>{err_message}</p>
    {/if}
</form>

<style>
    form {
        border-radius: 4px;
        border-color: grey;
        border-style: solid;
        border-width: 2px;
        margin: auto;
        margin-top: 20px;
        width: 40%;
    }
    input {
        width: 80%;
        margin: auto;
    }
    p,
    h3 {
        margin-left: 10px;
        width: 100%;
    }
</style>
