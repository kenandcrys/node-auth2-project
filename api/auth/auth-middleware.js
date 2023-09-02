const { JWT_SECRET } = require("../secrets"); // use this secret!

const jwt = require("jsonwebtoken");

const restricted = (req, res, next) => {
  // Check if a token is provided in the Authorization header
  const token = req.headers.authorization;

  if (!token) {
    // If no token is provided, return a 401 response
    return res.status(401).json({
      message: "Token required"
    });
  }

  // Verify the provided token using the JWT_SECRET
  jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
    if (err) {
      // If the token is invalid, return a 401 response
      return res.status(401).json({
        message: "Token invalid"
      });
    }

    // If the token is valid, store the decoded token in the req object for downstream middlewares
    req.decodedToken = decodedToken;
    next();
  });
};
const only = (role_name) => (req, res, next) => {
  // Check if a decoded token exists in the req object
  const decodedToken = req.decodedToken;

  if (!decodedToken || decodedToken.role_name !== role_name) {
    // If no decoded token exists or the role_name doesn't match, return a 403 response
    return res.status(403).json({
      message: "This is not for you"
    });
  }

  // If the role_name matches, allow the request to proceed
  next();
};


const checkUsernameExists = (req, res, next) => {
  // You will need to implement the logic to check if the username exists in the database.
  // Assuming you have a function called "usernameExistsInDatabase" for this purpose.

  // Example:
  const usernameExists = usernameExistsInDatabase(req.body.username);

  if (!usernameExists) {
    // If the username doesn't exist in the database, return a 401 response
    return res.status(401).json({
      message: "Invalid credentials"
    });
  }

  // If the username exists in the database, allow the request to proceed
  next();
};


const validateRoleName = (req, res, next) => {
  const role_name = req.body.role_name;

  if (!role_name || !role_name.trim()) {
    // If role_name is missing or an empty string, set it to 'student'
    req.role_name = 'student';
    next(); // Proceed to the next middleware
  } else if (role_name.trim() === 'admin') {
    // If role_name is 'admin', return a 422 response
    res.status(422).json({
      message: 'Role name can not be admin'
    });
  } else if (role_name.trim().length > 32) {
    // If role_name is longer than 32 characters, return a 422 response
    res.status(422).json({
      message: 'Role name can not be longer than 32 chars'
    });
  } else {
    // If role_name is valid, set req.role_name to the trimmed string and proceed
    req.role_name = role_name.trim();
    next();
  }
};


module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
