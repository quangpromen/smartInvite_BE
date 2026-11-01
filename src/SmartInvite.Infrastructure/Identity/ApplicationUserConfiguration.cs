using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SmartInvite.Application.Security;

namespace SmartInvite.Infrastructure.Identity;

public sealed class ApplicationUserConfiguration : IEntityTypeConfiguration<ApplicationUser>
{
    public void Configure(EntityTypeBuilder<ApplicationUser> builder)
    {
        builder.ToTable("AspNetUsers");

        builder.Property(u => u.Id)
            .ValueGeneratedNever();

        builder.Property(u => u.Email)
            .IsRequired()
            .HasMaxLength(IdentityFieldConstraints.MaxEmailLength);

        builder.Property(u => u.NormalizedEmail)
            .IsRequired()
            .HasMaxLength(IdentityFieldConstraints.MaxEmailLength);

        builder.HasIndex(u => u.NormalizedEmail)
            .HasDatabaseName("EmailIndex")
            .IsUnique()
            .HasFilter(null);

        builder.Property(u => u.UserName)
            .IsRequired()
            .HasMaxLength(IdentityFieldConstraints.MaxEmailLength);

        builder.Property(u => u.NormalizedUserName)
            .IsRequired()
            .HasMaxLength(IdentityFieldConstraints.MaxEmailLength);

        builder.HasIndex(u => u.NormalizedUserName)
            .HasDatabaseName("UserNameIndex")
            .IsUnique()
            .HasFilter(null);

        builder.Property(u => u.DisplayName)
            .IsRequired()
            .HasMaxLength(IdentityFieldConstraints.MaxDisplayNameLength);

        builder.Property(u => u.CreatedAt)
            .IsRequired();

        builder.Property(u => u.LastLoginAt);
    }
}
