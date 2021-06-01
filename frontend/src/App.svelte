<script>
	import RegisterForm from "./RegisterForm.svelte";
	import LoginForm from "./LoginForm.svelte";
	import Navbar from "./Navbar.svelte";

	let logged_in = false;

	fetch("http://localhost:8080/auth/logged_in").then(async function (
		response
	) {
		let data = await response.json();
		console.log(data);
		if (data.refresh) {
			logged_in = true;
		} else {
			logged_in = false;
		}
	});

	function login_happened(e) {
		logged_in = true;
		console.log("Login Happened");
	}
</script>

<div>
	<Navbar />
	{#if !logged_in}
		<LoginForm on:logged_in={login_happened} />
		<RegisterForm />
	{:else}
		<p>Something else</p>
	{/if}
</div>

<style>
</style>
