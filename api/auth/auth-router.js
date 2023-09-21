// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const router = require("express").Router();
const bcrypt = require("bcryptjs");
const Users = require("../users/users-model");
const {
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength,
} = require("../auth/auth-middleware");

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */

router.post(
  "/register",
  checkUsernameFree,
  checkPasswordLength,
  async (req, res) => {
    try {
      const { username, password } = req.body;
      const hash = await bcrypt.hash(password, 10);
      const [user] = await Users.add({ username, password: hash });
      console.log(user, "created");
      res.status(200).json({
        user_id: user,
        username,
        message: `Welcome ${username}!`,
      });
    } catch (err) {
      res.status(422).json({ message: err.message });
    }
  }
);

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */

router.post("/login", checkUsernameExists, checkPasswordLength, (req, res) => {
  let { username, password } = req.body;
  let user = req.user;
  console.log(user);
  if (user && bcrypt.compareSync(password, user.password)) {
    req.session.user = user;
    res.status(200).json({ message: `Welcome ${username}!` });
  } else {
    res.status(401).json({ message: "Invalid credentials" });
  }
});

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
router.get("/logout", (req, res) => {
  if (!req.session.user) {
    res.status(200).json({ message: "no session" });
  } else {
    req.session.destroy((err) => {
      if (err) {
        res.status(500).json({ message: "Error logging out" });
      } else {
        res.status(200).json({ message: "logged out" });
      }
    });
  }
});

// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;
