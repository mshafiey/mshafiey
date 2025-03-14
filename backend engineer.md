# **Application Security Fundamentals: Authentication, Authorization, and Encryption Techniques**

The imperative to secure modern applications has become paramount in the contemporary digital landscape. The escalating frequency and sophistication of cyber threats, coupled with stringent regulations concerning user data protection, necessitate a comprehensive understanding and implementation of robust security measures 1. At its core, application security strives to uphold the principles of the CIA triad: Confidentiality, Integrity, and Availability. Confidentiality ensures that sensitive information is accessible only to authorized entities, Integrity guarantees that data remains unaltered and trustworthy, and Availability ensures that authorized users can access resources when required 1. The topics explored within this report directly contribute to these fundamental principles, establishing a secure foundation for application development.

This report delves into key areas of application security, providing a detailed examination of authentication, authorization, encryption, and data integrity techniques. Authentication, the process of verifying the identity of users or systems, forms the initial barrier against unauthorized access. Authorization, which follows authentication, determines the specific actions that an authenticated user or system is permitted to perform. Encryption safeguards the confidentiality of data, both while it is being transmitted across networks and when it is stored in various systems. Finally, ensuring data integrity involves employing methods to confirm that data remains accurate and has not been subjected to unauthorized modifications. While security controls can be implemented at various layers, including network, host, and data levels, this report will primarily focus on security measures integrated directly within the application layer.

## **Basic HTTP Authentication**

### **Concept and Security Considerations**

Basic HTTP Authentication stands as a fundamental authentication scheme embedded directly within the Hypertext Transfer Protocol (HTTP). This built-in nature makes it a readily accessible mechanism for securing web resources across a multitude of platforms and development frameworks 3. The authentication process is straightforward: the client, typically a web browser or an application making an HTTP request, sends an Authorization header as part of the request. The value of this header is constructed by concatenating the word "Basic" with a space, followed by the Base64 encoding of the username and password, which are themselves joined by a colon. For instance, if the username is "admin" and the password is "secret", the encoded header value would be Basic YWRtaW46c2VjcmV0 3.

One of the primary appeals of Basic HTTP Authentication is its relative ease of implementation. Often, integrating this scheme into an application requires minimal code, making it a seemingly convenient option for securing simple applications or for rapid prototyping 3. However, this simplicity is accompanied by significant security vulnerabilities that render it unsuitable for most production environments where sensitive data is handled.

A critical security flaw lies in the use of Base64 encoding. It is crucial to understand that Base64 is not an encryption algorithm; it merely obfuscates data by encoding it into a different format. This encoding is easily reversible, meaning that the original username and password can be readily retrieved by anyone who intercepts the Authorization header 3. Consequently, transmitting credentials in this manner, especially over unencrypted HTTP connections, exposes them to a high risk of interception and decoding by malicious actors 3. This susceptibility significantly increases the likelihood of Man-in-the-Middle (MITM) attacks, where an attacker can eavesdrop on the communication between the client and the server, capturing the Base64 encoded credentials and subsequently decoding them to gain unauthorized access 3. The inherent weakness of transmitting weakly protected credentials makes Basic HTTP Authentication over plain HTTP a major security risk, potentially leading to unauthorized access to protected resources.

Given these severe security limitations, it is an absolute necessity to employ Basic HTTP Authentication exclusively over secure HTTPS connections 3. HTTPS utilizes Transport Layer Security (TLS) or its predecessor, Secure Sockets Layer (SSL), to encrypt the entire communication between the client and the server. This encryption extends to the Authorization header, thereby protecting the Base64 encoded credentials from interception and decoding during transit. Without HTTPS, the minimal security offered by Basic Authentication is entirely negated, leaving credentials vulnerable to even rudimentary eavesdropping techniques.

Furthermore, as a precautionary measure, it is strongly advised to avoid logging the Authorization header or any part of the raw credentials on the server side 3. Logs, while essential for debugging and monitoring, can inadvertently expose sensitive information if not handled with extreme care. Including plain text or easily decodable credentials in server logs creates an additional avenue for potential security breaches, as attackers who gain access to these logs can readily obtain valid usernames and passwords.

It is also important to note that Basic HTTP Authentication is increasingly being deprecated in favor of more robust and secure authentication mechanisms in modern web applications and Application Programming Interfaces (APIs) 6. Contemporary security best practices often favor token-based authentication (such as JWT) or OAuth-based authentication, which offer enhanced security features, including protection against replay attacks and more granular control over access permissions. The shift away from Basic Auth reflects a growing understanding of its inherent weaknesses and a commitment to adopting more secure authentication paradigms within the development community.

### **Implementation in Go**

The Go programming language, often used for building backend services, provides various ways to implement Basic HTTP Authentication. One straightforward method, particularly when using the popular Gin web framework, involves leveraging built-in middleware. Gin offers the gin.BasicAuth middleware, which can be easily integrated into route definitions to protect specific resources 3. This middleware utilizes a gin.Accounts map, where usernames are keys and their corresponding passwords are values. When a request is made to a route protected by this middleware, Gin automatically checks for the Authorization header. If the header is missing or the provided credentials do not match the accounts defined in the gin.Accounts map, the server responds with a 401 Unauthorized status code and includes a WWW-Authenticate header in the response, prompting the client to provide valid credentials 4. Clients can typically include the Basic Auth header by embedding the username and password directly within the URL in the format http://username:password@resource\_url.com/ 3.

Go

`package main`

`import (`  
	`"net/http"`

	`"github.com/gin-gonic/gin"`  
`)`

`func main() {`  
	`r := gin.Default()`  
	`protected := r.Group("/auth")`  
	`protected.Use(gin.BasicAuth(gin.Accounts{`  
		`"admin": "secret",`  
		`"guest": "password",`  
	`}))`  
	`{`  
		`protected.GET("/resource", func(c *gin.Context) {`  
			`c.JSON(http.StatusOK, gin.H{"data": "protected resource data"})`  
		`})`  
	`}`  
	`r.Run(":8080")`  
`}`

In this example, the /auth/resource endpoint is protected by Basic Authentication, requiring either "admin:secret" or "guest:password" credentials.

Alternatively, developers can manually implement Basic Auth in Go by extracting and decoding the Authorization header. This involves retrieving the header value using c.GetHeader("Authorization"), checking if it starts with "Basic ", and then decoding the Base64 encoded part 3. The decoded string will contain the username and password separated by a colon. It is then crucial to securely compare these extracted credentials against stored user information. For production applications, it is highly recommended to store password hashes using a strong hashing algorithm like bcrypt, as demonstrated in snippet8, which provides an example of a simple HTTPS server using basic authentication with bcrypt for password comparison. Manual implementation offers more control over the authentication process but also places a greater responsibility on the developer to ensure security best practices are followed.

Go

`package main`

`import (`  
	`"encoding/base64"`  
	`"fmt"`  
	`"net/http"`  
	`"strings"`

	`"github.com/gin-gonic/gin"`  
`)`

`func basicAuthMiddleware() gin.HandlerFunc {`  
	`return func(c *gin.Context) {`  
		`authHeader := c.GetHeader("Authorization")`  
		`if !strings.HasPrefix(authHeader, "Basic ") {`  
			`c.AbortWithStatus(http.StatusUnauthorized)`  
			`return`  
		`}`

		`encodedCredentials := strings.TrimPrefix(authHeader, "Basic ")`  
		`decodedCredentials, err := base64.StdEncoding.DecodeString(encodedCredentials)`  
		`if err != nil {`  
			`c.AbortWithStatus(http.StatusUnauthorized)`  
			`return`  
		`}`

		`parts := strings.SplitN(string(decodedCredentials), ":", 2)`  
		`if len(parts) != 2 {`  
			`c.AbortWithStatus(http.StatusUnauthorized)`  
			`return`  
		`}`

		`username := parts`  
		`password := parts[1]`

		`// In a real application, you would compare these against a database`  
		`if username == "testuser" && password == "testpassword" {`  
			`c.Next() // Proceed to the next handler`  
		`} else {`  
			`c.AbortWithStatus(http.StatusUnauthorized)`  
		`}`  
	`}`  
`}`

`func main() {`  
	`r := gin.Default()`  
	`r.GET("/protected", basicAuthMiddleware(), func(c *gin.Context) {`  
		`c.JSON(http.StatusOK, gin.H{"message": "Access granted"})`  
	`})`  
	`r.Run(":8080")`  
`}`

### **Implementation in Python**

Python offers several convenient ways to handle Basic HTTP Authentication, both for making authenticated requests and for implementing it on the server side. When acting as a client, the requests library provides a straightforward approach 5. One method involves using the auth parameter in the requests.get() (or other HTTP methods) function, passing a tuple containing the username and password as arguments 5. The requests library will automatically handle the Base64 encoding and the setting of the Authorization header.

Python

`import requests`

`# Using the auth parameter`  
`response = requests.get('http://localhost:8080/protected', auth=('admin', 'secret'))`  
`print(response.status_code)`  
`print(response.text)`

`# Manually setting the Authorization header`  
`import base64`

`username = "admin"`  
`password = "secret"`  
`credentials = f'{username}:{password}'`  
`encoded_credentials = base64.b64encode(credentials.encode()).decode()`  
`headers = {'Authorization': f'Basic {encoded_credentials}'}`  
`response = requests.get('http://localhost:8080/protected', headers=headers)`  
`print(response.status_code)`  
`print(response.text)`

Alternatively, the Authorization header can be set manually. This involves creating the username and password string, encoding it in Base64, and then including it in the Authorization header with the "Basic " prefix 5. For applications that need to make multiple authenticated requests to the same server, it is efficient to use a requests.Session object. By setting the authentication credentials on the session, subsequent requests made with that session will automatically include the necessary Authorization header 9.

On the server side, frameworks like FastAPI provide tools for implementing Basic Auth. FastAPI's fastapi.security module includes HTTPBasic, which can be used as a dependency to protect API endpoints 6. By using Depends(security), where security \= HTTPBasic(), FastAPI will automatically expect and validate the Basic Auth credentials provided in the request. Developers can then define a verification function that takes HTTPBasicCredentials as input (which includes the username and password) and checks them against a stored set of users. FastAPI handles the WWW-Authenticate header and the 401 Unauthorized response automatically if the authentication fails. The concept of realms, as mentioned in snippets4 and4, can be used with Basic Auth to partition protected spaces within an application, potentially requiring different credentials for different realms.

Python

`from fastapi import FastAPI, Depends, HTTPException, status`  
`from fastapi.security import HTTPBasic, HTTPBasicCredentials`

`security = HTTPBasic()`  
`app = FastAPI()`

`users = {"admin": {"password": "Password123"}}`

`def get_current_user(credentials: HTTPBasicCredentials = Depends(security)):`  
    `user_dict = users.get(credentials.username)`  
    `if not user_dict or not credentials.password == user_dict["password"]:`  
        `raise HTTPException(`  
            `status_code=status.HTTP_401_UNAUTHORIZED,`  
            `detail="Incorrect username or password",`  
            `headers={"WWW-Authenticate": "Basic"},`  
        `)`  
    `return credentials.username`

`@app.get("/protected")`  
`async def protected_route(current_user: str = Depends(get_current_user)):`  
    `return {"message": f"Hello, {current_user}! This is a protected resource."}`

### **Implementation in C\#**

In C\#, making web API calls with Basic HTTP Authentication can be achieved using the HttpClient class 12. This involves creating an instance of HttpClient and then setting the Authorization header in the default request headers. The header value should be "Basic " followed by the Base64 encoded username and password. The encoding can be done using Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}")).

C\#

`using System;`  
`using System.Net.Http;`  
`using System.Net.Http.Headers;`  
`using System.Text;`  
`using System.Threading.Tasks;`

`public class Example`  
`{`  
    `public static async Task CallProtectedResource()`  
    `{`  
        `string username = "testuser";`  
        `string password = "testpassword";`  
        `string url = "http://localhost:8080/protected";`

        `using (var client = new HttpClient())`  
        `{`  
            `var authValue = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}")));`  
            `client.DefaultRequestHeaders.Authorization = authValue;`

            `HttpResponseMessage response = await client.GetAsync(url);`  
            `if (response.IsSuccessStatusCode)`  
            `{`  
                `string content = await response.Content.ReadAsStringAsync();`  
                `Console.WriteLine($"Response: {content}");`  
            `}`  
            `else`  
            `{`  
                `Console.WriteLine($"Error: {response.StatusCode}");`  
            `}`  
        `}`  
    `}`  
`}`

For older .NET frameworks, HttpWebRequest along with NetworkCredential can also be used, as shown in snippet12.

Implementing Basic Authentication on the server side in ASP.NET Core can be done by creating custom middleware 15. This middleware would inspect the Authorization header of each incoming request. If the header is present and starts with "Basic ", the middleware would then decode the Base64 encoded credentials to extract the username and password. These extracted credentials can then be validated against a store of users (e.g., from a database). If the credentials are valid, the request is allowed to proceed to the next stage in the pipeline; otherwise, the middleware can return a 401 Unauthorized response. This approach provides fine-grained control over the authentication process and allows for custom logic in validating users.

C\#

`using Microsoft.AspNetCore.Builder;`  
`using Microsoft.AspNetCore.Http;`  
`using System;`  
`using System.Net;`  
`using System.Net.Http.Headers;`  
`using System.Text;`  
`using System.Threading.Tasks;`

`public class BasicAuthMiddleware`  
`{`  
    `private readonly RequestDelegate _next;`  
    `private readonly string _username;`  
    `private readonly string _password;`

    `public BasicAuthMiddleware(RequestDelegate next, string username, string password)`  
    `{`  
        `_next = next;`  
        `_username = username;`  
        `_password = password;`  
    `}`

    `public async Task InvokeAsync(HttpContext context)`  
    `{`  
        `if (!context.Request.Headers.ContainsKey("Authorization"))`  
        `{`  
            `await Unauthorized(context);`  
            `return;`  
        `}`

        `var authHeader = AuthenticationHeaderValue.Parse(context.Request.Headers["Authorization"]);`  
        `if (authHeader.Scheme != "Basic")`  
        `{`  
            `await Unauthorized(context);`  
            `return;`  
        `}`

        `var credentialsBytes = Convert.FromBase64String(authHeader.Parameter);`  
        `var credentials = Encoding.UTF8.GetString(credentialsBytes).Split(':', 2);`  
        `var username = credentials;`  
        `var password = credentials[1];`

        `if (username == _username && password == _password)`  
        `{`  
            `await _next(context);`  
            `return;`  
        `}`

        `await Unauthorized(context);`  
    `}`

    `private async Task Unauthorized(HttpContext context)`  
    `{`  
        `context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;`  
        `context.Response.Headers.Add("WWW-Authenticate", "Basic");`  
        `await context.Response.WriteAsync("Unauthorized");`  
    `}`  
`}`

`public static class BasicAuthMiddlewareExtensions`  
`{`  
    `public static IApplicationBuilder UseBasicAuth(this IApplicationBuilder builder, string username, string password)`  
    `{`  
        `return builder.UseMiddleware<BasicAuthMiddleware>(username, password);`  
    `}`  
`}`

This middleware can then be added to the Configure method in Startup.cs:

C\#

`public void Configure(IApplicationBuilder app, IWebHostEnvironment env)`  
`{`  
    `// ... other middleware ...`

    `app.UseBasicAuth("admin", "secret");`

    `app.UseRouting();`

    `// ... other middleware ...`  
`}`

## **Role-Based Access Control (RBAC)**

### **Concept and Benefits**

Role-Based Access Control (RBAC) is a widely adopted authorization mechanism that governs user access to resources and functionalities based on the roles assigned to them within a system or organization 16. Instead of granting permissions directly to individual users, RBAC defines roles, which are collections of permissions that dictate what users holding that role are allowed to do 16. Common examples of roles include "Administrator," "Editor," and "Viewer," each associated with a specific set of permissions, such as "read," "write," or "delete" 16.

The implementation of RBAC offers several significant benefits for application security and manageability. Firstly, it enhances security by adhering to the principle of least privilege 16. Users are granted only the necessary permissions to perform their tasks, minimizing the potential for accidental or malicious misuse of resources. This targeted access control reduces the attack surface and limits the damage that a compromised account can inflict.

Secondly, RBAC simplifies user and permission management 16. Assigning roles to users is a more efficient process than managing individual permissions for each user, especially in large and complex systems. When a new user joins, they are simply assigned the appropriate role(s), inheriting the associated permissions. Similarly, when a user's responsibilities change, their roles can be updated accordingly. This role-based approach significantly reduces administrative overhead and makes the system more manageable as the user base and resource landscape evolve.

Furthermore, RBAC promotes scalability 16. As an application grows and new features are introduced, permissions for these features can be readily associated with existing or new roles. This allows the access control model to adapt to changes in the application without requiring modifications to individual user permissions. The structure provided by RBAC makes it easier to reason about and manage access rights as the application's functionality expands.

Finally, roles often reflect real-world organizational structures or job responsibilities 19. This alignment makes the access control model more intuitive and easier for administrators and auditors to understand and verify. The semantic relevance of roles simplifies the process of defining and maintaining appropriate access levels across the organization or system.

### **Implementation in Go**

In Go, a basic form of RBAC can be implemented using middleware within web frameworks like Gin. This often involves checking for the presence of a specific token in the Authorization header, where the token's value might implicitly represent a certain role. For instance, any request containing a predefined "secret\_token" could be considered to have administrative privileges 7.

Go

`package main`

`import (`  
	`"net/http"`

	`"github.com/gin-gonic/gin"`  
`)`

`func AuthMiddleware() gin.HandlerFunc {`  
	`return func(c *gin.Context) {`  
		`token := c.GetHeader("Authorization")`  
		`if token != "secret_token" {`  
			`c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})`  
			`c.Abort()`  
			`return`  
		`}`  
		`c.Next()`  
	`}`  
`}`

`func main() {`  
	`r := gin.Default()`  
	`r.GET("/admin/resource", AuthMiddleware(), func(c *gin.Context) {`  
		`c.JSON(http.StatusOK, gin.H{"data": "Admin resource"})`  
	`})`  
	`r.Run(":8080")`  
`}`

In this simplified example, only requests with the Authorization header set to "secret\_token" will be able to access the /admin/resource endpoint.

For a more comprehensive RBAC implementation in Go, it is common to interact with a database to store information about users, roles, and the permissions associated with each role 16. A typical database schema might include tables such as users, roles, access (defining specific permissions), user\_role (linking users to their assigned roles), and role\_access (mapping permissions to roles) 16.

A core component of such an implementation is a function, often named something like HasAccess, which takes a userID and an accessName (permission) as input 16. This function would then query the database to determine if the user, through their assigned role(s), possesses the specified permission. This involves joining the aforementioned tables to trace the relationship between the user and the requested permission.

Go

`// Assuming a database connection 'Db' is established`

`func HasAccess(userID int, accessName string) bool {`  
	`var count int`  
	`` query := ` ``  
		`SELECT COUNT(*)`  
		`FROM users u`  
		`JOIN user_role ur ON u.id = ur.user_id`  
		`JOIN role_access ra ON ur.role_id = ra.role_id`  
		`JOIN access a ON ra.access_id = a.access_id`  
		`WHERE u.id = $1 AND a.access_name = $2`  
	`` ` ``  
	`err := Db.QueryRow(query, userID, accessName).Scan(&count)`  
	`if err != nil {`  
		`// Handle error appropriately, e.g., log it`  
		`return false`  
	`}`  
	`return count > 0`  
`}`

To protect specific API routes based on these permissions, middleware can be used. An RBACMiddleware function can be created, which takes the required permission as an argument and returns a Gin handler function 16. This middleware would first retrieve the userID from the Gin context (assuming it was set during authentication). Then, it would call the HasAccess function to check if the user has the necessary permission. If not, the middleware would return an "HTTP 403 Forbidden" error and abort the request. Otherwise, it would call c.Next() to allow the request to proceed to the actual route handler.

Go

`func RBACMiddleware(permission string) gin.HandlerFunc {`  
	`return func(c *gin.Context) {`  
		`userIDInterface, exists := c.Get("id")`  
		`if !exists {`  
			`c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})`  
			`c.Abort()`  
			`return`  
		`}`  
		`userID, ok := userIDInterface.(int)`  
		`if !ok {`  
			`c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid User ID format"})`  
			`c.Abort()`  
			`return`  
		`}`

		`if !HasAccess(userID, permission) {`  
			`c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})`  
			`c.Abort()`  
			`return`  
		`}`  
		`c.Next()`  
	`}`  
`}`

`func SetupRoutes(r *gin.Engine) {`  
	`// ... other routes ...`  
	`authGroup := r.Group("/")`  
	`// authGroup.Use(middleware.AuthMiddleware()) // Middleware to authenticate user and set 'id' in context`  
	`authGroup.GET("/users", RBACMiddleware("read"), func(c *gin.Context) {`  
		`// Handler for getting users`  
		`c.JSON(http.StatusOK, gin.H{"message": "Users data"})`  
	`})`  
	`authGroup.PUT("/users/:id", RBACMiddleware("update"), func(c *gin.Context) {`  
		`// Handler for updating a user`  
		`userID := c.Param("id")`  
		`c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("User %s updated", userID)})`  
	`})`  
	`// ... other protected routes ...`  
`}`

### **Implementation in Python**

Python offers libraries like Oso that facilitate the implementation of RBAC using a policy-based approach 20. Oso allows developers to define authorization rules in a declarative policy language, separate from the application's core logic. This promotes cleaner code and easier management of access controls. An example involves defining actors (users), resources, roles, and permissions in a .polar policy file. Within the Python application, the Oso library can then be used to query this policy to determine if a user (actor) has the necessary permission to perform an action on a specific resource.

Python

`from oso import Oso, Value`

`oso = Oso()`  
`oso.load_files(["policy.polar"])`

`class User:`  
    `def __init__(self, id, roles):`  
        `self.id = id`  
        `self.roles = roles`

`class Repository:`  
    `def __init__(self, name):`  
        `self.name = name`

`current_user = User(1, ["contributor"])`  
`repo = Repository("my-repo")`

`if oso.authorize(Value("User", current_user), "read", Value("Repository", repo)):`  
    `print("User has read access to the repository.")`  
`else:`  
    `print("User does not have read access to the repository.")`

The corresponding policy.polar file might contain rules like:

Code snippet

`actor User {}`  
`resource Repository {`  
    `permissions = ["read", "push"];`  
    `roles = ["contributor", "maintainer"];`  
    `"read" if "contributor";`  
    `"push" if "maintainer";`  
`}`

This policy defines that a User has the "read" permission on a Repository if they have the "contributor" role.

Furthermore, frameworks like Flask and FastAPI in Python allow for implementing RBAC using decorators. These decorators can be used to specify the roles that are allowed to access a particular route or function. When a request is made, the framework checks if the authenticated user's role matches the required roles defined by the decorator.

### **Implementation in C\#**

ASP.NET Core provides robust support for implementing RBAC through the \[Authorize\] attribute and authorization policies 23. The \[Authorize\] attribute can be applied to controllers or individual action methods to restrict access based on user roles. For instance, would only allow users belonging to the "Admin" role to access the decorated resource. Multiple roles can be specified using comma separation, such as. To require a user to be in all specified roles, multiple \[Authorize\] attributes can be applied. The \[AllowAnonymous\] attribute can be used to permit unauthenticated access to specific actions within an otherwise authorized controller.

C\#

`using Microsoft.AspNetCore.Authorization;`  
`using Microsoft.AspNetCore.Mvc;`

`public class AdminController : ControllerBase`  
`{`  
    `[HttpGet]`  
    `public IActionResult Index()`  
    `{`  
        `return Ok("Welcome, Administrator!");`  
    `}`

    `[AllowAnonymous]`  
    `[HttpGet("public")]`  
    `public IActionResult PublicEndpoint()`  
    `{`  
        `return Ok("This endpoint is accessible to everyone.");`  
    `}`  
`}`

`public class EditorController : ControllerBase`  
`{`  
    `[HttpGet]`  
    `public IActionResult Edit()`  
    `{`  
        `return Ok("Editor access granted.");`  
    `}`  
`}`

Before using role-based authorization, the necessary services need to be registered in the Program.cs file, typically by calling .AddRoles\<IdentityRole\>() within the Identity configuration 23. This requires the Microsoft.AspNetCore.Identity.UI package.

ASP.NET Core also allows for the creation of custom authorization policies, which can encapsulate more complex role-based requirements 24. This involves defining a policy with specific role requirements in the Program.cs file and then applying the policy to controllers or actions using the \[Authorize(Policy \= "PolicyName")\] attribute. Custom authorization handlers can be created to implement the logic for these policies, providing a more flexible and powerful way to manage role-based access control.

## **Cryptographic Hashing for Data Integrity**

### **Concept and Properties**

Cryptographic hash functions are indispensable tools in the realm of application security, primarily employed to ensure the integrity of data 1. These functions take an input of arbitrary size and produce a fixed-size output, commonly referred to as a hash value or a digest. This output acts as a unique fingerprint of the input data. Any alteration to the original input, no matter how small, will result in a significantly different hash value, making it possible to detect if data has been tampered with.

Several key properties define a secure cryptographic hash function. Firstly, it must be **deterministic** 28, meaning that for any given input, the hash function will always produce the same output. This consistency is crucial for reliably verifying data integrity. Secondly, the output of a cryptographic hash function has a **fixed size** 28, regardless of the size of the input. This fixed-length digest provides a concise representation of the original data. Thirdly, the process of computing the hash value from the input should be **computationally efficient** 28, allowing for quick generation of digests even for large datasets.

Furthermore, a secure cryptographic hash function exhibits **preimage resistance**, also known as the one-way property 28. Given a hash value, it should be computationally infeasible to find the original input that produced that hash. This property is fundamental for applications like password storage, where the hash of the password is stored instead of the password itself. Another important property is **second preimage resistance** 29. Given an input and its corresponding hash, it should be computationally infeasible to find a different input that produces the same hash value. This prevents attackers from substituting a modified version of data that has the same hash as the original.

**Collision resistance** is another critical property 29. It should be computationally infeasible to find two distinct inputs that produce the same hash output (a collision). While the pigeonhole principle dictates that collisions must exist for any hash function (as the input space is larger than the output space), a secure cryptographic hash function makes finding such collisions extremely difficult. Lastly, a good cryptographic hash function demonstrates the **avalanche effect** 31, where even a minor change in the input data (such as flipping a single bit) results in a drastically different hash output. This sensitivity to input changes is essential for easily detecting data tampering.

Cryptographic hashing finds widespread applications in various security-sensitive contexts. One of the most common uses is in **password storage** 30. Instead of storing user passwords in plain text, which would be catastrophic if the system were compromised, applications store the hash of the password. When a user attempts to log in, the system hashes the entered password and compares it to the stored hash. If they match, the user is authenticated without the system ever needing to know the actual password.

Another key application is in **data integrity verification** 29. By calculating the hash of a file or message before it is transmitted or stored, and then recalculating the hash at the destination or upon retrieval, one can verify if the data has been altered during transit or storage. If the hash values match, it confirms that the data has remained intact.

Cryptographic hashes are also integral to **digital signatures** 30. In a digital signature scheme, a hash of a document is created and then signed using the sender's private key (in asymmetric cryptography). Anyone with the sender's public key can then verify the signature and, by extension, the authenticity and integrity of the document.

Among the various cryptographic hash functions available, SHA256 (Secure Hash Algorithm 256-bit) is widely adopted and currently considered a secure choice for many applications 28. It produces a 256-bit (32-byte) hash value and offers a good balance of security and performance for a wide range of use cases.

### **SHA256 Hashing Examples in Go**

The Go programming language provides built-in support for SHA256 hashing through the crypto/sha256 package 30. The following code snippet demonstrates how to compute the SHA256 hash of a string in Go:

Go

`package main`

`import (`  
	`"crypto/sha256"`  
	`"fmt"`  
`)`

`func main() {`  
	`s := "sha256 this string"`  
	`h := sha256.New() // Creates a new SHA256 hash object`  
	`h.Write(byte(s)) // Writes the string (as a byte slice) to the hash object`  
	`bs := h.Sum(nil)   // Computes the final hash and returns it as a byte slice`  
	`fmt.Println(s)`  
	`fmt.Printf("%x\n", bs) // Prints the hash in hexadecimal format`  
`}`

In this example, sha256.New() initializes a new SHA256 hash object. The string s is then converted to a byte slice using byte(s) and written to the hash object using h.Write(). The h.Sum(nil) method calculates the final hash value and returns it as a slice of bytes. Finally, fmt.Printf("%x\\n", bs) formats the byte slice bs into a hexadecimal string for easy readability.

### **SHA256 Hashing Examples in Python**

Python's hashlib module offers a convenient way to work with various hashing algorithms, including SHA256 32. Here's an example of how to compute the SHA256 hash of a string in Python:

Python

`import hashlib`

`input_string = "Hello, world!"`  
`hash_object = hashlib.sha256(input_string.encode()) # Creates a SHA256 hash object and updates it with the encoded string`  
`hex_digest = hash_object.hexdigest() # Gets the hexadecimal representation of the hash digest`  
`print(f"SHA-256 Hash: {hex_digest}")`

In this code, hashlib.sha256(input\_string.encode()) creates a SHA256 hash object. The input string is first encoded into bytes using .encode() as hash functions typically operate on binary data. The hexdigest() method then returns the computed hash value as a string of hexadecimal characters.

### **SHA256 Hashing Examples in C\#**

C\# provides the System.Security.Cryptography.SHA256 class for performing SHA256 hashing 33. The following code snippet demonstrates how to generate the SHA256 hash of a string in C\#:

C\#

`using System;`  
`using System.Security.Cryptography;`  
`using System.Text;`

`public class Example`  
`{`  
    `public static string GenerateSHA256Hash(string input)`  
    `{`  
        `using (SHA256 sha256Hash = SHA256.Create()) // Creates an instance of the SHA256 class`  
        `{`  
            `byte bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(input)); // Computes the hash of the input string (as bytes)`  
            `StringBuilder builder = new StringBuilder();`  
            `for (int i = 0; i < bytes.Length; i++)`  
            `{`  
                `builder.Append(bytes[i].ToString("x2")); // Converts each byte to its hexadecimal string representation`  
            `}`  
            `return builder.ToString();`  
        `}`  
    `}`

    `public static void Main(string args)`  
    `{`  
        `string inputString = "Hello, Geeks!";`  
        `string hashValue = GenerateSHA256Hash(inputString);`  
        `Console.WriteLine($"SHA256 Hash: {hashValue}");`  
    `}`  
`}`

Here, SHA256.Create() creates a new instance of the SHA256 algorithm. The input string is converted to a byte array using Encoding.UTF8.GetBytes(), and sha256Hash.ComputeHash() calculates the hash. The resulting byte array is then iterated through, and each byte is converted to its hexadecimal representation (two lowercase characters) and appended to a StringBuilder. Finally, the ToString() method of the StringBuilder returns the complete hexadecimal hash string.

## **Symmetric Encryption: AES**

### **Concept and Use Cases**

Symmetric encryption is a fundamental category of encryption algorithms that employ the same secret key for both the process of transforming plaintext into an unreadable format (ciphertext) and the reverse process of decrypting ciphertext back into its original plaintext form 1. This reliance on a single, shared secret key is the defining characteristic of symmetric encryption.

One of the primary advantages of symmetric encryption is its speed and efficiency 44. Compared to asymmetric encryption, symmetric algorithms generally require less computational power, making them significantly faster for encrypting and decrypting large amounts of data. This efficiency makes them particularly well-suited for scenarios where performance is critical. Another advantage is the relative simplicity of the concept and implementation 44. Using a single key for both encryption and decryption can be easier to understand and manage in certain contexts.

However, the most significant challenge associated with symmetric encryption is the necessity of secure key distribution 45. Because the same key is used for both encryption and decryption, it must be securely shared between all parties who need to communicate using the encrypted data. If this secret key falls into the hands of an unauthorized individual, the confidentiality of all data encrypted with that key is compromised.

The Advanced Encryption Standard (AES) stands out as the most widely adopted and a highly secure symmetric block cipher in contemporary cryptography 47. AES operates on fixed-size blocks of data, typically 128 bits, and supports key sizes of 128, 192, or 256 bits. The strength of the encryption is directly related to the key size used, with 256-bit keys offering the highest level of security.

AES finds extensive use in a wide array of applications. It is commonly employed for encrypting large amounts of data at rest, such as files stored on a computer or data residing in databases 58. It also plays a crucial role in securing communication channels, such as those established by Virtual Private Networks (VPNs) and the Transport Layer Security (TLS) and Secure Sockets Layer (SSL) protocols that underpin secure web browsing (HTTPS) 1. Furthermore, AES is used to secure wireless networks, with protocols like WPA3 relying on it to encrypt data transmitted over Wi-Fi 67.

When using block ciphers like AES, the mode of operation is a critical consideration. Different modes dictate how the cipher is applied to multiple blocks of data and can significantly impact the security properties of the encryption 51. Common modes include Cipher Block Chaining (CBC), Galois/Counter Mode (GCM), and Counter (CTR) mode. Galois/Counter Mode (GCM) is often recommended as it provides authenticated encryption, which means it not only ensures the confidentiality of the data but also generates an authentication tag that can be used to verify the integrity of the ciphertext, detecting any unauthorized modifications 51.

### **AES Implementation in Go**

Go's crypto/aes package, in conjunction with the crypto/cipher package, provides the necessary tools for implementing AES encryption and decryption 51. The following example demonstrates AES encryption using Cipher Block Chaining (CBC) mode:

Go

`package main`

`import (`  
	`"bytes"`  
	`"crypto/aes"`  
	`"crypto/cipher"`  
	`"crypto/rand"`  
	`"fmt"`  
	`"io"`  
	`"os"`  
`)`

`func pad(srcbyte, blockSize int)byte {`  
	`padding := blockSize - len(src)%blockSize`  
	`padtext := bytes.Repeat(byte{byte(padding)}, padding)`  
	`return append(src, padtext...)`  
`}`

`func unpad(srcbyte)byte {`  
	`length := len(src)`  
	`unpadding := int(src[length-1])`  
	`return src[:(length - unpadding)]`  
`}`

`func encryptCBC(plaintextbyte, keybyte)byte {`  
	`block, err := aes.NewCipher(key)`  
	`if err != nil {`  
		`panic(err)`  
	`}`  
	`blockSize := block.BlockSize()`  
	`plaintext = pad(plaintext, blockSize)`  
	`ciphertext := make(byte, blockSize+len(plaintext))`  
	`iv := ciphertext`  
	`if _, err := io.ReadFull(rand.Reader, iv); err != nil {`  
		`panic(err)`  
	`}`  
	`mode := cipher.NewCBCEncrypter(block, iv)`  
	`mode.CryptBlocks(ciphertext, plaintext)`  
	`return ciphertext`  
`}`

`func decryptCBC(ciphertextbyte, keybyte)byte {`  
	`block, err := aes.NewCipher(key)`  
	`if err != nil {`  
		`panic(err)`  
	`}`  
	`blockSize := block.BlockSize()`  
	`if len(ciphertext) < blockSize {`  
		`panic("ciphertext too short")`  
	`}`  
	`iv := ciphertext`  
	`ciphertext = ciphertext`  
	`if len(ciphertext)%blockSize != 0 {`  
		`panic("ciphertext is not a multiple of the block size")`  
	`}`  
	`mode := cipher.NewCBCDecrypter(block, iv)`  
	`mode.CryptBlocks(ciphertext, ciphertext)`  
	`return unpad(ciphertext)`  
`}`

`func main() {`  
	`key :=byte("thisisatestkey1234567890") // Must be 16, 24, or 32 bytes for AES-128, 192, or 256`  
	`plaintext :=byte("This is some sensitive data!")`  
	`ciphertext := encryptCBC(plaintext, key)`  
	`fmt.Printf("Ciphertext: %x\n", ciphertext)`  
	`decryptedtext := decryptCBC(ciphertext, key)`  
	`fmt.Printf("Decrypted: %s\n", string(decryptedtext))`  
`}`

This example demonstrates encryption and decryption using CBC mode. It includes pad and unpad functions to handle the block size requirement of AES. A random Initialization Vector (IV) is generated for each encryption operation and prepended to the ciphertext.

For authenticated encryption, Go's crypto/cipher package offers Galois/Counter Mode (GCM):

Go

`package main`

`import (`  
	`"crypto/aes"`  
	`"crypto/cipher"`  
	`"crypto/rand"`  
	`"fmt"`  
	`"io"`  
`)`

`func encryptGCM(plaintextbyte, keybyte)byte {`  
	`block, err := aes.NewCipher(key)`  
	`if err != nil {`  
		`panic(err)`  
	`}`  
	`gcm, err := cipher.NewGCM(block)`  
	`if err != nil {`  
		`panic(err)`  
	`}`  
	`nonce := make(byte, gcm.NonceSize())`  
	`if _, err := io.ReadFull(rand.Reader, nonce); err != nil {`  
		`panic(err)`  
	`}`  
	`ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)`  
	`return ciphertext`  
`}`

`func decryptGCM(ciphertextbyte, keybyte)byte {`  
	`block, err := aes.NewCipher(key)`  
	`if err != nil {`  
		`panic(err)`  
	`}`  
	`gcm, err := cipher.NewGCM(block)`  
	`if err != nil {`  
		`panic(err)`  
	`}`  
	`nonceSize := gcm.NonceSize()`  
	`if len(ciphertext) < nonceSize {`  
		`panic("ciphertext too short")`  
	`}`  
	`nonce, ciphertext := ciphertext, ciphertext`  
	`plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)`  
	`if err != nil {`  
		`panic(err)`  
	`}`  
	`return plaintext`  
`}`

`func main() {`  
	`key :=byte("thisisatestkey1234567890123456") // Must be 16, 24, or 32 bytes`  
	`plaintext :=byte("This is some sensitive data!")`  
	`ciphertext := encryptGCM(plaintext, key)`  
	`fmt.Printf("Ciphertext (GCM): %x\n", ciphertext)`  
	`decryptedtext := decryptGCM(ciphertext, key)`  
	`fmt.Printf("Decrypted (GCM): %s\n", string(decryptedtext))`  
`}`

This GCM example generates a random nonce for each encryption and prepends it to the ciphertext. The gcm.Seal method encrypts and authenticates the data, while gcm.Open decrypts and verifies the authentication tag.

### **AES Implementation in Python**

Python's pycryptodome library provides a comprehensive set of cryptographic primitives, including AES 54. Here's an example using AES in EAX mode for authenticated encryption:

Python

`from Crypto.Cipher import AES`  
`from Crypto.Random import get_random_bytes`

`def encrypt_eax(plaintext, key):`  
    `cipher = AES.new(key, AES.MODE_EAX)`  
    `ciphertext, tag = cipher.encrypt_and_digest(plaintext)`  
    `nonce = cipher.nonce`  
    `return nonce, ciphertext, tag`

`def decrypt_eax(nonce, ciphertext, tag, key):`  
    `cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)`  
    `plaintext = cipher.decrypt_and_verify(ciphertext, tag)`  
    `return plaintext`

`key = get_random_bytes(16) # Generate a random 16-byte key`  
`plaintext = b'This is some sensitive data!'`  
`nonce, ciphertext, tag = encrypt_eax(plaintext, key)`  
`print(f"Nonce: {nonce.hex()}")`  
`print(f"Ciphertext: {ciphertext.hex()}")`  
`print(f"Tag: {tag.hex()}")`

`decrypted_text = decrypt_eax(nonce, ciphertext, tag, key)`  
`print(f"Decrypted: {decrypted_text.decode()}")`

This code uses AES.MODE\_EAX for authenticated encryption. The encrypt\_and\_digest method returns both the ciphertext and an authentication tag. The nonce (number used once) is also returned and is essential for decryption. The decrypt\_and\_verify method decrypts the ciphertext and also verifies the integrity of the data using the provided tag. If the tag is invalid (indicating tampering), a ValueError is raised.

### **AES Implementation in C\#**

C\# offers the System.Security.Cryptography.Aes class for AES encryption 59. The following example demonstrates AES encryption and decryption using CBC mode with PKCS7 padding:

C\#

`using System;`  
`using System.IO;`  
`using System.Security.Cryptography;`  
`using System.Text;`

`public class Example`  
`{`  
    `public static byte EncryptCBC(byte data, byte key, byte iv)`  
    `{`  
        `using (Aes aesAlg = Aes.Create())`  
        `{`  
            `aesAlg.Key = key;`  
            `aesAlg.IV = iv;`  
            `aesAlg.Mode = CipherMode.CBC;`  
            `aesAlg.Padding = PaddingMode.PKCS7;`

            `ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);`

            `using (MemoryStream msEncrypt = new MemoryStream())`  
            `{`  
                `using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))`  
                `{`

#### **Works cited**

1\. What is Cryptography? \- AWS, accessed March 14, 2025, [https://aws.amazon.com/what-is/cryptography/](https://aws.amazon.com/what-is/cryptography/)  
2\. What Is Cryptography? | IBM, accessed March 14, 2025, [https://www.ibm.com/think/topics/cryptography](https://www.ibm.com/think/topics/cryptography)  
3\. Authentication for Go Applications: The Secure Way \- JetBrains Guide, accessed March 14, 2025, [https://www.jetbrains.com/guide/go/tutorials/authentication-for-go-apps/auth/](https://www.jetbrains.com/guide/go/tutorials/authentication-for-go-apps/auth/)  
4\. How to correctly use Basic Authentication in Go \- Alex Edwards, accessed March 14, 2025, [https://www.alexedwards.net/blog/basic-authentication-in-go](https://www.alexedwards.net/blog/basic-authentication-in-go)  
5\. Basic Authentication \- Lightcast API, accessed March 14, 2025, [https://docs.lightcast.dev/guides/basic-authentication](https://docs.lightcast.dev/guides/basic-authentication)  
6\. Implementing Basic Authentication With Python FastAPI | by Ariel Torres | Medium, accessed March 14, 2025, [https://pykestrel.medium.com/implementing-basic-authentication-with-python-fastapi-12f9718ff0ad](https://pykestrel.medium.com/implementing-basic-authentication-with-python-fastapi-12f9718ff0ad)  
7\. Implementing Basic Authentication in Go with Gin | by Nova Novriansyah \- Medium, accessed March 14, 2025, [https://medium.com/novai-go-programming-101/implementing-basic-authentication-in-go-with-gin-cf1a7beb5263](https://medium.com/novai-go-programming-101/implementing-basic-authentication-in-go-with-gin-cf1a7beb5263)  
8\. https-basic-auth-server.go \- GitHub, accessed March 14, 2025, [https://github.com/eliben/code-for-blog/blob/master/2021/go-rest-servers/auth/basic-sample/https-basic-auth-server.go](https://github.com/eliben/code-for-blog/blob/master/2021/go-rest-servers/auth/basic-sample/https-basic-auth-server.go)  
9\. Basic Authentication with Python in less than 60 Seconds\! \- YouTube, accessed March 14, 2025, [https://www.youtube.com/watch?v=ocUvQBV8SiY](https://www.youtube.com/watch?v=ocUvQBV8SiY)  
10\. Authentication using Python requests \- GeeksforGeeks, accessed March 14, 2025, [https://www.geeksforgeeks.org/authentication-using-python-requests/](https://www.geeksforgeeks.org/authentication-using-python-requests/)  
11\. Handling basic API authentication using requests in Python | by Brahma Rao Kothapalli, accessed March 14, 2025, [https://medium.com/@brahmaraokothapalli/handling-basic-api-authentication-using-requests-in-python-63f11610567c](https://medium.com/@brahmaraokothapalli/handling-basic-api-authentication-using-requests-in-python-63f11610567c)  
12\. Calling WEB API with basic authentication in C\# \- Stack Overflow, accessed March 14, 2025, [https://stackoverflow.com/questions/57665326/calling-web-api-with-basic-authentication-in-c-sharp](https://stackoverflow.com/questions/57665326/calling-web-api-with-basic-authentication-in-c-sharp)  
13\. How to use Basic Auth with HttpClient? \- Microsoft Q\&A, accessed March 14, 2025, [https://learn.microsoft.com/en-us/answers/questions/1187341/how-to-use-basic-auth-with-httpclient](https://learn.microsoft.com/en-us/answers/questions/1187341/how-to-use-basic-auth-with-httpclient)  
14\. Call api with basic authentication using c\# | by Pramod Choudhari | Medium, accessed March 14, 2025, [https://medium.com/@pramod.choudhari/call-api-with-basic-authentication-using-c-7ae56c85a6f3](https://medium.com/@pramod.choudhari/call-api-with-basic-authentication-using-c-7ae56c85a6f3)  
15\. How to implement Basic Authentication client in C\#/.NET \- YouTube, accessed March 14, 2025, [https://www.youtube.com/watch?v=fpggaU4po7s](https://www.youtube.com/watch?v=fpggaU4po7s)  
16\. Mastering Role-Based Access Control (RBAC) in Go: A Step-by ..., accessed March 14, 2025, [https://medium.com/@smart\_byte\_labs/mastering-role-based-access-control-rbac-in-go-a-step-by-step-guide-bda0fb64f100](https://medium.com/@smart_byte_labs/mastering-role-based-access-control-rbac-in-go-a-step-by-step-guide-bda0fb64f100)  
17\. Building RBAC in Golang \- Aserto, accessed March 14, 2025, [https://www.aserto.com/blog/building-rbac-in-go](https://www.aserto.com/blog/building-rbac-in-go)  
18\. Build Role-Based Access Control (RBAC) in Go with Oso, accessed March 14, 2025, [https://www.osohq.com/docs/oss/go/guides/rbac.html](https://www.osohq.com/docs/oss/go/guides/rbac.html)  
19\. How to Implement Role-Based Access Control (RBAC) Authorization in Golang \- Permit.io, accessed March 14, 2025, [https://www.permit.io/blog/role-based-access-control-rbac-authorization-in-golang](https://www.permit.io/blog/role-based-access-control-rbac-authorization-in-golang)  
20\. Build Role-Based Access Control (RBAC) in Python with Oso, accessed March 14, 2025, [https://www.osohq.com/docs/oss/guides/rbac.html](https://www.osohq.com/docs/oss/guides/rbac.html)  
21\. How to implement Role Based Access Control (RBAC) in Python \- Oso, accessed March 14, 2025, [https://www.osohq.com/learn/rbac-python](https://www.osohq.com/learn/rbac-python)  
22\. Basic Authentication in Go Using Middleware (Non JWT) | by Nova Novriansyah \- Medium, accessed March 14, 2025, [https://medium.com/novai-go-programming-101/basic-authentication-in-go-using-middleware-non-jwt-43a0edccac6d](https://medium.com/novai-go-programming-101/basic-authentication-in-go-using-middleware-non-jwt-43a0edccac6d)  
23\. Role-based authorization in ASP.NET Core | Microsoft Learn, accessed March 14, 2025, [https://learn.microsoft.com/en-us/aspnet/core/security/authorization/roles?view=aspnetcore-9.0](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/roles?view=aspnetcore-9.0)  
24\. Role based Authorization in .NET Core: A Beginner's Guide with ..., accessed March 14, 2025, [https://dotnetfullstackdev.medium.com/role-based-authorization-in-net-core-a-beginners-guide-with-code-snippets-b952e5b952f7](https://dotnetfullstackdev.medium.com/role-based-authorization-in-net-core-a-beginners-guide-with-code-snippets-b952e5b952f7)  
25\. Simple authorization in ASP.NET Core \- Microsoft Learn, accessed March 14, 2025, [https://learn.microsoft.com/en-us/aspnet/core/security/authorization/simple?view=aspnetcore-9.0](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/simple?view=aspnetcore-9.0)  
26\. Role-based authorization for action without one for controller \- Stack Overflow, accessed March 14, 2025, [https://stackoverflow.com/questions/79292842/role-based-authorization-for-action-without-one-for-controller](https://stackoverflow.com/questions/79292842/role-based-authorization-for-action-without-one-for-controller)  
27\. Implementing Role-Based Authorization in ASP.NET Core 8 Web API: Best Practices for Secure and Scalable APIs | by Samuel Getachew | Medium, accessed March 14, 2025, [https://medium.com/@solomongetachew112/implementing-role-based-authorization-in-asp-net-c259f919fb5d](https://medium.com/@solomongetachew112/implementing-role-based-authorization-in-asp-net-c259f919fb5d)  
28\. What is a Cryptographic Hashing Function? (Example \+ Purpose) \- YouTube, accessed March 14, 2025, [https://www.youtube.com/watch?v=gTfNtop9vzM](https://www.youtube.com/watch?v=gTfNtop9vzM)  
29\. Cryptographic Hash Functions: Definition and Examples \- Investopedia, accessed March 14, 2025, [https://www.investopedia.com/news/cryptographic-hash-functions/](https://www.investopedia.com/news/cryptographic-hash-functions/)  
30\. A Tour of Go Cryptography Part 1: Hashing | by Bryant Hagadorn | Medium, accessed March 14, 2025, [https://medium.com/@bryant.hagadorn/a-tour-of-go-cryptography-part-1-hashing-421f565f02e9](https://medium.com/@bryant.hagadorn/a-tour-of-go-cryptography-part-1-hashing-421f565f02e9)  
31\. Cryptographic hash functions \- IBM Quantum Learning, accessed March 14, 2025, [https://learning.quantum.ibm.com/course/practical-introduction-to-quantum-safe-cryptography/cryptographic-hash-functions](https://learning.quantum.ibm.com/course/practical-introduction-to-quantum-safe-cryptography/cryptographic-hash-functions)  
32\. Cryptographic Hash Functions in Python: Secure Your Data Easily ..., accessed March 14, 2025, [https://www.stackzero.net/cryptographic-hash-functions-in-python-secure-your-data-easily/](https://www.stackzero.net/cryptographic-hash-functions-in-python-secure-your-data-easily/)  
33\. HashAlgorithm Class (System.Security.Cryptography) | Microsoft Learn, accessed March 14, 2025, [https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.hashalgorithm?view=net-9.0](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.hashalgorithm?view=net-9.0)  
34\. What You Need To Know About Hashing in Python \- Kinsta®, accessed March 14, 2025, [https://kinsta.com/blog/python-hashing/](https://kinsta.com/blog/python-hashing/)  
35\. SHA256 Hashes \- Go by Example, accessed March 14, 2025, [https://gobyexample.com/sha256-hashes](https://gobyexample.com/sha256-hashes)  
36\. Cryptographic Hash Function Golang \- YouTube, accessed March 14, 2025, [https://www.youtube.com/watch?v=EpcChcZgWVE](https://www.youtube.com/watch?v=EpcChcZgWVE)  
37\. Hash Function for String data in C\# \- GeeksforGeeks, accessed March 14, 2025, [https://www.geeksforgeeks.org/hash-function-for-string-data-in-c-sharp/](https://www.geeksforgeeks.org/hash-function-for-string-data-in-c-sharp/)  
38\. Hash string in c\# \- Stack Overflow, accessed March 14, 2025, [https://stackoverflow.com/questions/3984138/hash-string-in-c-sharp](https://stackoverflow.com/questions/3984138/hash-string-in-c-sharp)  
39\. c\# \- Which cryptographic hash function should I choose? \- Stack Overflow, accessed March 14, 2025, [https://stackoverflow.com/questions/800685/which-cryptographic-hash-function-should-i-choose](https://stackoverflow.com/questions/800685/which-cryptographic-hash-function-should-i-choose)  
40\. MD5 hash in Python \- GeeksforGeeks, accessed March 14, 2025, [https://www.geeksforgeeks.org/md5-hash-python/](https://www.geeksforgeeks.org/md5-hash-python/)  
41\. Cryptography Explained | University of Phoenix, accessed March 14, 2025, [https://www.phoenix.edu/blog/what-is-cryptography.html](https://www.phoenix.edu/blog/what-is-cryptography.html)  
42\. What is Cryptography? \- Kaspersky, accessed March 14, 2025, [https://www.kaspersky.com/resource-center/definitions/what-is-cryptography](https://www.kaspersky.com/resource-center/definitions/what-is-cryptography)  
43\. deviceauthority.com, accessed March 14, 2025, [https://deviceauthority.com/symmetric-encryption-vs-asymmetric-encryption/\#:\~:text=There%20are%20two%20basic%20types,a%20private%20key%20for%20decryption.](https://deviceauthority.com/symmetric-encryption-vs-asymmetric-encryption/#:~:text=There%20are%20two%20basic%20types,a%20private%20key%20for%20decryption.)  
44\. Symmetric Encryption vs Asymmetric Encryption: How it Works and Why it's Used, accessed March 14, 2025, [https://deviceauthority.com/symmetric-encryption-vs-asymmetric-encryption/](https://deviceauthority.com/symmetric-encryption-vs-asymmetric-encryption/)  
45\. Symmetric vs. Asymmetric Encryption: What's the Difference? \- Trenton Systems, accessed March 14, 2025, [https://www.trentonsystems.com/en-us/resource-hub/blog/symmetric-vs-asymmetric-encryption](https://www.trentonsystems.com/en-us/resource-hub/blog/symmetric-vs-asymmetric-encryption)  
46\. Symmetric vs. Asymmetric Encryption \- What are differences? \- Cheap SSL Certificates, accessed March 14, 2025, [https://www.ssl2buy.com/wiki/symmetric-vs-asymmetric-encryption-what-are-differences](https://www.ssl2buy.com/wiki/symmetric-vs-asymmetric-encryption-what-are-differences)  
47\. Encryption choices: rsa vs. aes explained \- Prey, accessed March 14, 2025, [https://preyproject.com/blog/types-of-encryption-symmetric-or-asymmetric-rsa-or-aes](https://preyproject.com/blog/types-of-encryption-symmetric-or-asymmetric-rsa-or-aes)  
48\. Pros and cons of symmetric algorithms: Ensuring security and efficiency \- Passwork Pro, accessed March 14, 2025, [https://passwork.pro/blog/symmetric-algorithms/](https://passwork.pro/blog/symmetric-algorithms/)  
49\. An Overview of Symmetric Encryption and the Key Lifecycle \- Cryptomathic, accessed March 14, 2025, [https://www.cryptomathic.com/blog/an-overview-of-symmetric-encryption-and-the-key-lifecycle](https://www.cryptomathic.com/blog/an-overview-of-symmetric-encryption-and-the-key-lifecycle)  
50\. What's the Difference Between Symmetric vs Asymmetric Encryption? \- Trustifi, accessed March 14, 2025, [https://trustifi.com/blog/difference-between-symmetric-vs-asymmetric-encryption/](https://trustifi.com/blog/difference-between-symmetric-vs-asymmetric-encryption/)  
51\. Encrypting with AES — Bitfield Consulting, accessed March 14, 2025, [https://bitfieldconsulting.com/posts/aes-encryption](https://bitfieldconsulting.com/posts/aes-encryption)  
52\. Secret Key Encryption with Go using AES \- DEV Community, accessed March 14, 2025, [https://dev.to/breda/secret-key-encryption-with-go-using-aes-316d](https://dev.to/breda/secret-key-encryption-with-go-using-aes-316d)  
53\. Encrypt and Decrypt Data in Go with AES-256 | Twilio, accessed March 14, 2025, [https://www.twilio.com/en-us/blog/encrypt-and-decrypt-data-in-go-with-aes-256](https://www.twilio.com/en-us/blog/encrypt-and-decrypt-data-in-go-with-aes-256)  
54\. AES Encryption & Decryption In Python: Implementation, Modes ..., accessed March 14, 2025, [https://onboardbase.com/blog/aes-encryption-decryption/](https://onboardbase.com/blog/aes-encryption-decryption/)  
55\. Practical-Cryptography-for-Developers-Book/symmetric-key-ciphers/aes-encrypt-decrypt-examples.md at master \- GitHub, accessed March 14, 2025, [https://github.com/nakov/Practical-Cryptography-for-Developers-Book/blob/master/symmetric-key-ciphers/aes-encrypt-decrypt-examples.md](https://github.com/nakov/Practical-Cryptography-for-Developers-Book/blob/master/symmetric-key-ciphers/aes-encrypt-decrypt-examples.md)  
56\. AES-256 Cipher – Python Cryptography Examples \- DEV Community, accessed March 14, 2025, [https://dev.to/wagslane/aes-256-cipher-python-cryptography-examples-10b2](https://dev.to/wagslane/aes-256-cipher-python-cryptography-examples-10b2)  
57\. AES Encrytion Example in Python \- GitHub Gist, accessed March 14, 2025, [https://gist.github.com/wowkin2/a2b234c87290f6959c815d3c21336278](https://gist.github.com/wowkin2/a2b234c87290f6959c815d3c21336278)  
58\. How to Encrypt and Decrypt Files in Python Using AES: A Step-by-Step Guide \- Medium, accessed March 14, 2025, [https://medium.com/@dheeraj.mickey/how-to-encrypt-and-decrypt-files-in-python-using-aes-a-step-by-step-guide-d0eb6f525e4e](https://medium.com/@dheeraj.mickey/how-to-encrypt-and-decrypt-files-in-python-using-aes-a-step-by-step-guide-d0eb6f525e4e)  
59\. C\# AES Encryption (How It Works For Developers) \- IronPDF, accessed March 14, 2025, [https://ironpdf.com/blog/net-help/csharp-aes-encryption/](https://ironpdf.com/blog/net-help/csharp-aes-encryption/)  
60\. Aes Class (System.Security.Cryptography) \- Microsoft Learn, accessed March 14, 2025, [https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes?view=net-9.0](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes?view=net-9.0)  
61\. AES Encryption in Action: Encrypt & Decrypt Data in C\# (Step-by-Step) \- YouTube, accessed March 14, 2025, [https://www.youtube.com/watch?v=wYgkiT1fSik](https://www.youtube.com/watch?v=wYgkiT1fSik)  
62\. Implementing AES Encryption With C\#, accessed March 14, 2025, [https://www.milanjovanovic.tech/blog/implementing-aes-encryption-with-csharp](https://www.milanjovanovic.tech/blog/implementing-aes-encryption-with-csharp)  
63\. A sample code that demonstrates a typical AES Encryption/Decryption with C\# · GitHub, accessed March 14, 2025, [https://gist.github.com/mazhar-ansari-ardeh/d200d91fbafc1af03a0bc0588ef7ffd0](https://gist.github.com/mazhar-ansari-ardeh/d200d91fbafc1af03a0bc0588ef7ffd0)  
64\. When to Use Symmetric Encryption vs Asymmetric Encryption \- Keyfactor, accessed March 14, 2025, [https://www.keyfactor.com/blog/symmetric-vs-asymmetric-encryption/](https://www.keyfactor.com/blog/symmetric-vs-asymmetric-encryption/)  
65\. Symmetric Encryption Algorithms \- Bugcrowd, accessed March 14, 2025, [https://www.bugcrowd.com/glossary/symmetric-encryption-algorithms/](https://www.bugcrowd.com/glossary/symmetric-encryption-algorithms/)  
66\. Popular Symmetric Algorithms | Practical Cryptography for Developers, accessed March 14, 2025, [https://cryptobook.nakov.com/symmetric-key-ciphers/popular-symmetric-algorithms](https://cryptobook.nakov.com/symmetric-key-ciphers/popular-symmetric-algorithms)  
67\. Data Encryption Methods & Types: A Beginner's Guide | Splunk, accessed March 14, 2025, [https://www.splunk.com/en\_us/blog/learn/data-encryption-methods-types.html](https://www.splunk.com/en_us/blog/learn/data-encryption-methods-types.html)  
68\. AES encryption of files in Go \- Eli Bendersky's website, accessed March 14, 2025, [https://eli.thegreenplace.net/2019/aes-encryption-of-files-in-go/](https://eli.thegreenplace.net/2019/aes-encryption-of-files-in-go/)  
69\. A quick example of basic AES encryption using the Golang AES library. \- GitHub Gist, accessed March 14, 2025, [https://gist.github.com/DaaaaanB/03acf29a90684c2afc9487152324e832](https://gist.github.com/DaaaaanB/03acf29a90684c2afc9487152324e832)