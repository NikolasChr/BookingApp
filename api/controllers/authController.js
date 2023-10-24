import User from "../models/User.js";
import bcrypt from "bcryptjs";
import { createError } from "../utils/error.js";
import jwt from "jsonwebtoken";

export const register = async (req, res, next) => {
  try {
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(req.body.password, salt);
    const newUser = new User({
      username: req.body.username,
      email: req.body.email,
      password: hash,
    });

    await newUser.save();
    res.status(200).send("User has been created !");
  } catch (err) {
    next(err);
  }
};
export const login = async (req, res, next) => {
  try {
    const loggedUser = await User.findOne({ username: req.body.username });
    if (!loggedUser) {
      return next(createError(404, "User not found"));
    }

    const isPasswordCorrect = await bcrypt.compare(
      req.body.password,
      loggedUser.password
    );
    if (!isPasswordCorrect) {
      return next(createError(400, "Incorrect Password or Username."));
    }
    const token = jwt.sign(
      {
        id: loggedUser._id,
        isAdmin: loggedUser.isAdmin,
      },
      process.env.JWT
    );
    const { password, isAdmin, ...otherDetails } = loggedUser._doc;
    res
      .cookie("access_token", token, { httpOnly: true })
      .status(200)
      .json({ ...otherDetails });
  } catch (err) {
    next(err);
  }
};
