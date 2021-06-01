<script>
    import { createEventDispatcher } from "svelte";

    let handle;
    let password;

    const dispatch = createEventDispatcher();

    let err_message = "";

    async function onSubmit(e) {
        e.preventDefault();

        let request = {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ handle: handle, password: password }),
        };

        fetch("http://localhost:8080/auth/login", request).then(async function (
            r
        ) {
            let response = await r;

            if (response.status === 200) {
                console.log("Login Success");
                dispatch("logged_in", "success");
            }
        });
    }
</script>

<form on:submit={onSubmit}>
    <h3>Login</h3>
    <p>
        <label for="handle">Account Handle</label>
        <input id="handle" type="text" placeholder="" bind:value={handle} />
    </p>
    <p>
        <label for="password">Password</label>
        <input id="password" type="password" bind:value={password} />
    </p>
    <p>
        <input type="submit" value="Login" />
    </p>
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
        margin-top: 10px;
        margin-left: 10px;
    }
</style>
