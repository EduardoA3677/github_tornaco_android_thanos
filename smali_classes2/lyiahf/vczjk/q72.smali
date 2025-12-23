.class public final Llyiahf/vczjk/q72;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/oO0Oo0oo;

.field public final synthetic OooO0O0:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oO0Oo0oo;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/q72;->OooO0O0:I

    const-string p2, "delegate"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/q72;->OooO00o:Llyiahf/vczjk/oO0Oo0oo;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/vp3;Llyiahf/vczjk/a12;Llyiahf/vczjk/v02;)Z
    .locals 6

    iget v0, p0, Llyiahf/vczjk/q72;->OooO0O0:I

    packed-switch v0, :pswitch_data_0

    if-eqz p3, :cond_0

    invoke-static {p1, p2, p3}, Llyiahf/vczjk/j64;->OooO0O0(Llyiahf/vczjk/vp3;Llyiahf/vczjk/a12;Llyiahf/vczjk/v02;)Z

    move-result p1

    return p1

    :cond_0
    const/4 p1, 0x3

    new-array p1, p1, [Ljava/lang/Object;

    const/4 p2, 0x0

    const/4 p3, 0x1

    const-string v0, "from"

    aput-object v0, p1, p2

    const-string p2, "kotlin/reflect/jvm/internal/impl/load/java/JavaDescriptorVisibilities$3"

    aput-object p2, p1, p3

    const/4 p2, 0x2

    const-string p3, "isVisible"

    aput-object p3, p1, p2

    const-string p2, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalArgumentException;

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2

    :pswitch_0
    if-eqz p3, :cond_1

    invoke-static {p1, p2, p3}, Llyiahf/vczjk/j64;->OooO0O0(Llyiahf/vczjk/vp3;Llyiahf/vczjk/a12;Llyiahf/vczjk/v02;)Z

    move-result p1

    return p1

    :cond_1
    const/4 p1, 0x3

    new-array p1, p1, [Ljava/lang/Object;

    const/4 p2, 0x0

    const/4 p3, 0x1

    const-string v0, "from"

    aput-object v0, p1, p2

    const-string p2, "kotlin/reflect/jvm/internal/impl/load/java/JavaDescriptorVisibilities$2"

    aput-object p2, p1, p3

    const/4 p2, 0x2

    const-string p3, "isVisible"

    aput-object p3, p1, p2

    const-string p2, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalArgumentException;

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2

    :pswitch_1
    if-eqz p3, :cond_2

    invoke-static {p2, p3}, Llyiahf/vczjk/j64;->OooO0OO(Llyiahf/vczjk/a12;Llyiahf/vczjk/v02;)Z

    move-result p1

    return p1

    :cond_2
    const/4 p1, 0x3

    new-array p1, p1, [Ljava/lang/Object;

    const/4 p2, 0x1

    const/4 p3, 0x0

    const/4 v0, 0x2

    const-string v1, "from"

    aput-object v1, p1, p3

    const-string p3, "kotlin/reflect/jvm/internal/impl/load/java/JavaDescriptorVisibilities$1"

    aput-object p3, p1, p2

    const-string p2, "isVisible"

    aput-object p2, p1, v0

    const-string p2, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalArgumentException;

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2

    :pswitch_2
    if-eqz p3, :cond_3

    const/4 p1, 0x0

    return p1

    :cond_3
    const/4 p1, 0x3

    new-array p1, p1, [Ljava/lang/Object;

    const/4 p2, 0x0

    const/4 p3, 0x1

    const-string v0, "from"

    aput-object v0, p1, p2

    const-string p2, "kotlin/reflect/jvm/internal/impl/descriptors/DescriptorVisibilities$9"

    aput-object p2, p1, p3

    const/4 p2, 0x2

    const-string p3, "isVisible"

    aput-object p3, p1, p2

    const-string p2, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalArgumentException;

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2

    :pswitch_3
    if-eqz p3, :cond_4

    const/4 p1, 0x0

    return p1

    :cond_4
    const/4 p1, 0x3

    new-array p1, p1, [Ljava/lang/Object;

    const/4 p2, 0x0

    const/4 p3, 0x1

    const-string v0, "from"

    aput-object v0, p1, p2

    const-string p2, "kotlin/reflect/jvm/internal/impl/descriptors/DescriptorVisibilities$8"

    aput-object p2, p1, p3

    const/4 p2, 0x2

    const-string p3, "isVisible"

    aput-object p3, p1, p2

    const-string p2, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalArgumentException;

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2

    :pswitch_4
    if-nez p3, :cond_5

    const/4 p1, 0x3

    new-array p1, p1, [Ljava/lang/Object;

    const/4 p2, 0x0

    const/4 p3, 0x1

    const-string v0, "from"

    aput-object v0, p1, p2

    const-string p2, "kotlin/reflect/jvm/internal/impl/descriptors/DescriptorVisibilities$7"

    aput-object p2, p1, p3

    const/4 p2, 0x2

    const-string p3, "isVisible"

    aput-object p3, p1, p2

    const-string p2, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalArgumentException;

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2

    :cond_5
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "Visibility is unknown yet"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :pswitch_5
    if-nez p3, :cond_6

    const/4 p1, 0x3

    new-array p1, p1, [Ljava/lang/Object;

    const/4 p2, 0x0

    const/4 p3, 0x1

    const-string v0, "from"

    aput-object v0, p1, p2

    const-string p2, "kotlin/reflect/jvm/internal/impl/descriptors/DescriptorVisibilities$6"

    aput-object p2, p1, p3

    const/4 p2, 0x2

    const-string p3, "isVisible"

    aput-object p3, p1, p2

    const-string p2, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalArgumentException;

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2

    :cond_6
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "This method shouldn\'t be invoked for LOCAL visibility"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :pswitch_6
    const/4 p1, 0x1

    if-eqz p3, :cond_7

    return p1

    :cond_7
    const/4 p1, 0x3

    new-array p1, p1, [Ljava/lang/Object;

    const/4 p2, 0x0

    const/4 p3, 0x1

    const-string v0, "from"

    aput-object v0, p1, p2

    const-string p2, "kotlin/reflect/jvm/internal/impl/descriptors/DescriptorVisibilities$5"

    aput-object p2, p1, p3

    const/4 p2, 0x2

    const-string p3, "isVisible"

    aput-object p3, p1, p2

    const-string p2, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalArgumentException;

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2

    :pswitch_7
    const/4 p1, 0x1

    if-eqz p3, :cond_9

    invoke-static {p2}, Llyiahf/vczjk/n72;->OooO0Oo(Llyiahf/vczjk/v02;)Llyiahf/vczjk/cm5;

    move-result-object p2

    invoke-static {p3}, Llyiahf/vczjk/n72;->OooO0Oo(Llyiahf/vczjk/v02;)Llyiahf/vczjk/cm5;

    move-result-object p3

    invoke-interface {p3, p2}, Llyiahf/vczjk/cm5;->Ooooo00(Llyiahf/vczjk/cm5;)Z

    move-result p2

    if-nez p2, :cond_8

    const/4 p1, 0x0

    goto :goto_0

    :cond_8
    sget-object p2, Llyiahf/vczjk/r72;->OooOOOO:Llyiahf/vczjk/vn5;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :goto_0
    return p1

    :cond_9
    const/4 p1, 0x3

    new-array p1, p1, [Ljava/lang/Object;

    const/4 p2, 0x0

    const/4 p3, 0x1

    const-string v0, "from"

    aput-object v0, p1, p2

    const-string p2, "kotlin/reflect/jvm/internal/impl/descriptors/DescriptorVisibilities$4"

    aput-object p2, p1, p3

    const/4 p2, 0x2

    const-string p3, "isVisible"

    aput-object p3, p1, p2

    const-string p2, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalArgumentException;

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2

    :pswitch_8
    const/4 v0, 0x0

    const/4 v1, 0x1

    if-eqz p3, :cond_14

    const-class v2, Llyiahf/vczjk/by0;

    invoke-static {p2, v2, v1}, Llyiahf/vczjk/n72;->OooO(Llyiahf/vczjk/v02;Ljava/lang/Class;Z)Llyiahf/vczjk/v02;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/by0;

    const/4 v4, 0x0

    invoke-static {p3, v2, v4}, Llyiahf/vczjk/n72;->OooO(Llyiahf/vczjk/v02;Ljava/lang/Class;Z)Llyiahf/vczjk/v02;

    move-result-object p3

    check-cast p3, Llyiahf/vczjk/by0;

    if-nez p3, :cond_a

    goto :goto_2

    :cond_a
    if-eqz v3, :cond_b

    invoke-static {v3}, Llyiahf/vczjk/n72;->OooOO0o(Llyiahf/vczjk/v02;)Z

    move-result v5

    if-eqz v5, :cond_b

    invoke-static {v3, v2, v1}, Llyiahf/vczjk/n72;->OooO(Llyiahf/vczjk/v02;Ljava/lang/Class;Z)Llyiahf/vczjk/v02;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/by0;

    if-eqz v3, :cond_b

    invoke-interface {p3}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v5

    invoke-interface {v3}, Llyiahf/vczjk/by0;->OooO00o()Llyiahf/vczjk/by0;

    move-result-object v3

    invoke-static {v5, v3}, Llyiahf/vczjk/n72;->OooOOo(Llyiahf/vczjk/uk4;Llyiahf/vczjk/by0;)Z

    move-result v3

    if-eqz v3, :cond_b

    goto :goto_4

    :cond_b
    instance-of v3, p2, Llyiahf/vczjk/eo0;

    if-eqz v3, :cond_c

    move-object v3, p2

    check-cast v3, Llyiahf/vczjk/eo0;

    invoke-static {v3}, Llyiahf/vczjk/n72;->OooOo00(Llyiahf/vczjk/eo0;)Llyiahf/vczjk/eo0;

    move-result-object v3

    goto :goto_1

    :cond_c
    move-object v3, p2

    :goto_1
    invoke-static {v3, v2, v1}, Llyiahf/vczjk/n72;->OooO(Llyiahf/vczjk/v02;Ljava/lang/Class;Z)Llyiahf/vczjk/v02;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/by0;

    if-nez v2, :cond_d

    :goto_2
    move v1, v4

    goto :goto_4

    :cond_d
    invoke-interface {p3}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v4

    invoke-interface {v2}, Llyiahf/vczjk/by0;->OooO00o()Llyiahf/vczjk/by0;

    move-result-object v2

    invoke-static {v4, v2}, Llyiahf/vczjk/n72;->OooOOo(Llyiahf/vczjk/uk4;Llyiahf/vczjk/by0;)Z

    move-result v2

    if-eqz v2, :cond_13

    sget-object v2, Llyiahf/vczjk/r72;->OooOOO:Llyiahf/vczjk/wp3;

    if-ne p1, v2, :cond_e

    goto :goto_3

    :cond_e
    instance-of v2, v3, Llyiahf/vczjk/eo0;

    if-nez v2, :cond_f

    goto :goto_4

    :cond_f
    instance-of v2, v3, Llyiahf/vczjk/il1;

    if-eqz v2, :cond_10

    goto :goto_4

    :cond_10
    sget-object v2, Llyiahf/vczjk/r72;->OooOOO0:Llyiahf/vczjk/vp3;

    if-ne p1, v2, :cond_11

    goto :goto_4

    :cond_11
    sget-object v1, Llyiahf/vczjk/r72;->OooOO0o:Llyiahf/vczjk/up3;

    if-eq p1, v1, :cond_13

    if-nez p1, :cond_12

    goto :goto_3

    :cond_12
    invoke-virtual {p1}, Llyiahf/vczjk/vp3;->getType()Llyiahf/vczjk/uk4;

    throw v0

    :cond_13
    :goto_3
    invoke-interface {p3}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object p3

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/q72;->OooO00o(Llyiahf/vczjk/vp3;Llyiahf/vczjk/a12;Llyiahf/vczjk/v02;)Z

    move-result v1

    :goto_4
    return v1

    :cond_14
    const/4 p1, 0x3

    new-array p1, p1, [Ljava/lang/Object;

    const/4 p2, 0x1

    const/4 p3, 0x0

    const/4 v0, 0x2

    const-string v1, "from"

    aput-object v1, p1, p3

    const-string p3, "kotlin/reflect/jvm/internal/impl/descriptors/DescriptorVisibilities$3"

    aput-object p3, p1, p2

    const-string p2, "isVisible"

    aput-object p2, p1, v0

    const-string p2, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalArgumentException;

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2

    :pswitch_9
    const/4 v0, 0x1

    if-eqz p3, :cond_18

    sget-object v1, Llyiahf/vczjk/r72;->OooO00o:Llyiahf/vczjk/q72;

    invoke-virtual {v1, p1, p2, p3}, Llyiahf/vczjk/q72;->OooO00o(Llyiahf/vczjk/vp3;Llyiahf/vczjk/a12;Llyiahf/vczjk/v02;)Z

    move-result p3

    if-eqz p3, :cond_17

    sget-object p3, Llyiahf/vczjk/r72;->OooOOO0:Llyiahf/vczjk/vp3;

    if-ne p1, p3, :cond_15

    goto :goto_6

    :cond_15
    sget-object p3, Llyiahf/vczjk/r72;->OooOO0o:Llyiahf/vczjk/up3;

    if-ne p1, p3, :cond_16

    goto :goto_5

    :cond_16
    const-class p1, Llyiahf/vczjk/by0;

    invoke-static {p2, p1, v0}, Llyiahf/vczjk/n72;->OooO(Llyiahf/vczjk/v02;Ljava/lang/Class;Z)Llyiahf/vczjk/v02;

    move-result-object p1

    :cond_17
    :goto_5
    const/4 v0, 0x0

    :goto_6
    return v0

    :cond_18
    const/4 p1, 0x3

    new-array p1, p1, [Ljava/lang/Object;

    const/4 p2, 0x0

    const/4 p3, 0x1

    const-string v0, "from"

    aput-object v0, p1, p2

    const-string p2, "kotlin/reflect/jvm/internal/impl/descriptors/DescriptorVisibilities$2"

    aput-object p2, p1, p3

    const/4 p2, 0x2

    const-string p3, "isVisible"

    aput-object p3, p1, p2

    const-string p2, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalArgumentException;

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2

    :pswitch_a
    if-eqz p3, :cond_21

    invoke-static {p2}, Llyiahf/vczjk/n72;->OooOOoo(Llyiahf/vczjk/v02;)Z

    move-result p1

    if-eqz p1, :cond_19

    invoke-static {p3}, Llyiahf/vczjk/n72;->OooO0o(Llyiahf/vczjk/v02;)Llyiahf/vczjk/qp3;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/qp3;->OooOo0:Llyiahf/vczjk/qp3;

    if-eq p1, v0, :cond_19

    invoke-static {p2, p3}, Llyiahf/vczjk/r72;->OooO0Oo(Llyiahf/vczjk/a12;Llyiahf/vczjk/v02;)Z

    move-result p1

    goto :goto_a

    :cond_19
    instance-of p1, p2, Llyiahf/vczjk/il1;

    if-eqz p1, :cond_1a

    move-object p1, p2

    check-cast p1, Llyiahf/vczjk/il1;

    invoke-interface {p1}, Llyiahf/vczjk/il1;->OooOO0o()Llyiahf/vczjk/hz0;

    :cond_1a
    if-eqz p2, :cond_1c

    invoke-interface {p2}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object p2

    instance-of p1, p2, Llyiahf/vczjk/by0;

    if-eqz p1, :cond_1b

    invoke-static {p2}, Llyiahf/vczjk/n72;->OooOO0o(Llyiahf/vczjk/v02;)Z

    move-result p1

    if-eqz p1, :cond_1c

    :cond_1b
    instance-of p1, p2, Llyiahf/vczjk/hh6;

    if-eqz p1, :cond_1a

    :cond_1c
    if-nez p2, :cond_1d

    goto :goto_9

    :cond_1d
    :goto_7
    if-eqz p3, :cond_20

    if-ne p2, p3, :cond_1e

    goto :goto_8

    :cond_1e
    instance-of p1, p3, Llyiahf/vczjk/hh6;

    if-eqz p1, :cond_1f

    instance-of p1, p2, Llyiahf/vczjk/hh6;

    if-eqz p1, :cond_20

    move-object p1, p2

    check-cast p1, Llyiahf/vczjk/hh6;

    check-cast p1, Llyiahf/vczjk/ih6;

    move-object v0, p3

    check-cast v0, Llyiahf/vczjk/hh6;

    check-cast v0, Llyiahf/vczjk/ih6;

    iget-object p1, p1, Llyiahf/vczjk/ih6;->OooOo00:Llyiahf/vczjk/hc3;

    iget-object v0, v0, Llyiahf/vczjk/ih6;->OooOo00:Llyiahf/vczjk/hc3;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/hc3;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_20

    invoke-static {p3}, Llyiahf/vczjk/n72;->OooO0Oo(Llyiahf/vczjk/v02;)Llyiahf/vczjk/cm5;

    move-result-object p1

    invoke-static {p2}, Llyiahf/vczjk/n72;->OooO0Oo(Llyiahf/vczjk/v02;)Llyiahf/vczjk/cm5;

    move-result-object p2

    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_20

    :goto_8
    const/4 p1, 0x1

    goto :goto_a

    :cond_1f
    invoke-interface {p3}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object p3

    goto :goto_7

    :cond_20
    :goto_9
    const/4 p1, 0x0

    :goto_a
    return p1

    :cond_21
    const/4 p1, 0x3

    new-array p1, p1, [Ljava/lang/Object;

    const/4 p2, 0x0

    const/4 p3, 0x1

    const/4 v0, 0x2

    const-string v1, "from"

    aput-object v1, p1, p2

    const-string p2, "kotlin/reflect/jvm/internal/impl/descriptors/DescriptorVisibilities$1"

    aput-object p2, p1, p3

    const-string p2, "isVisible"

    aput-object p2, p1, v0

    const-string p2, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalArgumentException;

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q72;->OooO00o:Llyiahf/vczjk/oO0Oo0oo;

    invoke-virtual {v0}, Llyiahf/vczjk/oO0Oo0oo;->OooO0Oo()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
