class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  validates :name, presence: true
  validates :username, presence: true
  validates :username, uniqueness: true
  
  has_many :histories
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable

end
