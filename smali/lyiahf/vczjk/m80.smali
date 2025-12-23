.class public abstract Llyiahf/vczjk/m80;
.super Llyiahf/vczjk/m49;
.source "SourceFile"


# instance fields
.field protected final _supportsUpdates:Ljava/lang/Boolean;


# direct methods
.method public constructor <init>(Ljava/lang/Class;Ljava/lang/Boolean;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/m49;-><init>(Ljava/lang/Class;)V

    iput-object p2, p0, Llyiahf/vczjk/m80;->_supportsUpdates:Ljava/lang/Boolean;

    return-void
.end method

.method public static OoooOOO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/qa4;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/eb4;->o000OOo()Ljava/lang/Object;

    move-result-object p0

    if-nez p0, :cond_0

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p0, Llyiahf/vczjk/p46;->OooOOO0:Llyiahf/vczjk/p46;

    return-object p0

    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    const-class v1, [B

    if-ne v0, v1, :cond_2

    check-cast p0, [B

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    array-length p1, p0

    if-nez p1, :cond_1

    sget-object p0, Llyiahf/vczjk/yb0;->OooOOO0:Llyiahf/vczjk/yb0;

    return-object p0

    :cond_1
    new-instance p1, Llyiahf/vczjk/yb0;

    invoke-direct {p1, p0}, Llyiahf/vczjk/yb0;-><init>([B)V

    return-object p1

    :cond_2
    instance-of v0, p0, Llyiahf/vczjk/rg7;

    if-eqz v0, :cond_3

    check-cast p0, Llyiahf/vczjk/rg7;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p1, Llyiahf/vczjk/xg6;

    invoke-direct {p1, p0}, Llyiahf/vczjk/xg6;-><init>(Ljava/lang/Object;)V

    return-object p1

    :cond_3
    instance-of v0, p0, Llyiahf/vczjk/qa4;

    if-eqz v0, :cond_4

    check-cast p0, Llyiahf/vczjk/qa4;

    return-object p0

    :cond_4
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p1, Llyiahf/vczjk/xg6;

    invoke-direct {p1, p0}, Llyiahf/vczjk/xg6;-><init>(Ljava/lang/Object;)V

    return-object p1
.end method

.method public static OoooOOo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/pca;
    .locals 2

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0ooOoO()I

    move-result p1

    sget v0, Llyiahf/vczjk/m49;->OooOOO0:I

    and-int/2addr v0, p1

    sget-object v1, Llyiahf/vczjk/db4;->OooOOO:Llyiahf/vczjk/db4;

    if-eqz v0, :cond_2

    sget-object v0, Llyiahf/vczjk/w72;->OooOOO:Llyiahf/vczjk/w72;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/w72;->OooO0OO(I)Z

    move-result v0

    if-eqz v0, :cond_0

    sget-object p1, Llyiahf/vczjk/db4;->OooOOOO:Llyiahf/vczjk/db4;

    goto :goto_0

    :cond_0
    sget-object v0, Llyiahf/vczjk/w72;->OooOOOO:Llyiahf/vczjk/w72;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/w72;->OooO0OO(I)Z

    move-result p1

    if-eqz p1, :cond_1

    move-object p1, v1

    goto :goto_0

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/eb4;->o00000oO()Llyiahf/vczjk/db4;

    move-result-object p1

    goto :goto_0

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/eb4;->o00000oO()Llyiahf/vczjk/db4;

    move-result-object p1

    :goto_0
    sget-object v0, Llyiahf/vczjk/db4;->OooOOO0:Llyiahf/vczjk/db4;

    if-ne p1, v0, :cond_5

    invoke-virtual {p0}, Llyiahf/vczjk/eb4;->o00000o0()I

    move-result p0

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p1, Llyiahf/vczjk/r14;->OooOOO0:[Llyiahf/vczjk/r14;

    const/16 p1, 0xa

    if-gt p0, p1, :cond_4

    const/4 p1, -0x1

    if-ge p0, p1, :cond_3

    goto :goto_1

    :cond_3
    sget-object p2, Llyiahf/vczjk/r14;->OooOOO0:[Llyiahf/vczjk/r14;

    sub-int/2addr p0, p1

    aget-object p0, p2, p0

    return-object p0

    :cond_4
    :goto_1
    new-instance p1, Llyiahf/vczjk/r14;

    invoke-direct {p1, p0}, Llyiahf/vczjk/r14;-><init>(I)V

    return-object p1

    :cond_5
    if-ne p1, v1, :cond_6

    invoke-virtual {p0}, Llyiahf/vczjk/eb4;->o0000Ooo()J

    move-result-wide p0

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p2, Llyiahf/vczjk/t55;

    invoke-direct {p2, p0, p1}, Llyiahf/vczjk/t55;-><init>(J)V

    return-object p2

    :cond_6
    invoke-virtual {p0}, Llyiahf/vczjk/eb4;->OooOoOO()Ljava/math/BigInteger;

    move-result-object p0

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    if-nez p0, :cond_7

    sget-object p0, Llyiahf/vczjk/p46;->OooOOO0:Llyiahf/vczjk/p46;

    return-object p0

    :cond_7
    new-instance p1, Llyiahf/vczjk/xb0;

    invoke-direct {p1, p0}, Llyiahf/vczjk/xb0;-><init>(Ljava/math/BigInteger;)V

    return-object p1
.end method

.method public static OoooOo0(Ljava/lang/String;Llyiahf/vczjk/v72;)V
    .locals 2

    sget-object v0, Llyiahf/vczjk/w72;->OooOo0:Llyiahf/vczjk/w72;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v0

    if-nez v0, :cond_0

    return-void

    :cond_0
    filled-new-array {p0}, [Ljava/lang/Object;

    move-result-object p0

    const-string v0, "Duplicate field \'%s\' for `ObjectNode`: not allowed when `DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY` enabled"

    invoke-static {v0, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    new-instance v0, Llyiahf/vczjk/qj5;

    iget-object p1, p1, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    const-class v1, Llyiahf/vczjk/qa4;

    invoke-direct {v0, p1, p0, v1}, Llyiahf/vczjk/qj5;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Ljava/lang/Class;)V

    throw v0
.end method


# virtual methods
.method public final OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/u3a;->OooO0O0(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooOOO()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final OooOOOO(Llyiahf/vczjk/t72;)Ljava/lang/Boolean;
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/m80;->_supportsUpdates:Ljava/lang/Boolean;

    return-object p1
.end method

.method public final OoooOoO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/qa4;
    .locals 2

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->OooOoO()I

    move-result v0

    const/4 v1, 0x2

    if-eq v0, v1, :cond_4

    packed-switch v0, :pswitch_data_0

    iget-object p3, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    invoke-virtual {p2, p3, p1}, Llyiahf/vczjk/v72;->o000000o(Ljava/lang/Class;Llyiahf/vczjk/eb4;)V

    const/4 p1, 0x0

    throw p1

    :pswitch_0
    invoke-static {p1, p3}, Llyiahf/vczjk/m80;->OoooOOO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/qa4;

    move-result-object p1

    return-object p1

    :pswitch_1
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p1, Llyiahf/vczjk/p46;->OooOOO0:Llyiahf/vczjk/p46;

    return-object p1

    :pswitch_2
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p1, Llyiahf/vczjk/be0;->OooOOO:Llyiahf/vczjk/be0;

    return-object p1

    :pswitch_3
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p1, Llyiahf/vczjk/be0;->OooOOO0:Llyiahf/vczjk/be0;

    return-object p1

    :pswitch_4
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o00000oO()Llyiahf/vczjk/db4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/db4;->OooOOo:Llyiahf/vczjk/db4;

    if-ne v0, v1, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o00oO0o()Ljava/math/BigDecimal;

    move-result-object p1

    invoke-virtual {p3, p1}, Llyiahf/vczjk/ua4;->OooO00o(Ljava/math/BigDecimal;)Llyiahf/vczjk/pca;

    move-result-object p1

    return-object p1

    :cond_0
    sget-object v1, Llyiahf/vczjk/w72;->OooOOO0:Llyiahf/vczjk/w72;

    invoke-virtual {p2, v1}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result p2

    if-eqz p2, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o0o()Z

    move-result p2

    if-eqz p2, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0ooOO0()D

    move-result-wide p1

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p3, Llyiahf/vczjk/ud2;

    invoke-direct {p3, p1, p2}, Llyiahf/vczjk/ud2;-><init>(D)V

    return-object p3

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o00oO0o()Ljava/math/BigDecimal;

    move-result-object p1

    invoke-virtual {p3, p1}, Llyiahf/vczjk/ua4;->OooO00o(Ljava/math/BigDecimal;)Llyiahf/vczjk/pca;

    move-result-object p1

    return-object p1

    :cond_2
    sget-object p2, Llyiahf/vczjk/db4;->OooOOOo:Llyiahf/vczjk/db4;

    if-ne v0, p2, :cond_3

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o00000O()F

    move-result p1

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p2, Llyiahf/vczjk/y23;

    invoke-direct {p2, p1}, Llyiahf/vczjk/y23;-><init>(F)V

    return-object p2

    :cond_3
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0ooOO0()D

    move-result-wide p1

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p3, Llyiahf/vczjk/ud2;

    invoke-direct {p3, p1, p2}, Llyiahf/vczjk/ud2;-><init>(D)V

    return-object p3

    :pswitch_5
    invoke-static {p1, p2, p3}, Llyiahf/vczjk/m80;->OoooOOo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/pca;

    move-result-object p1

    return-object p1

    :pswitch_6
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1}, Llyiahf/vczjk/ua4;->OooO0O0(Ljava/lang/String;)Llyiahf/vczjk/en9;

    move-result-object p1

    return-object p1

    :pswitch_7
    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/m80;->Ooooo0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/f76;

    move-result-object p1

    return-object p1

    :cond_4
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p1, Llyiahf/vczjk/f76;

    invoke-direct {p1, p3}, Llyiahf/vczjk/f76;-><init>(Llyiahf/vczjk/ua4;)V

    return-object p1

    :pswitch_data_0
    .packed-switch 0x5
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

.method public final OoooOoo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/ky;
    .locals 2

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Llyiahf/vczjk/ky;

    invoke-direct {v0, p3}, Llyiahf/vczjk/ky;-><init>(Llyiahf/vczjk/ua4;)V

    :goto_0
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/gc4;->OooO0OO()I

    move-result v1

    packed-switch v1, :pswitch_data_0

    :pswitch_0
    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/m80;->OoooOoO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/qa4;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ky;->OooO0o(Llyiahf/vczjk/qa4;)V

    goto :goto_0

    :pswitch_1
    invoke-static {p1, p3}, Llyiahf/vczjk/m80;->OoooOOO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/qa4;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ky;->OooO0o(Llyiahf/vczjk/qa4;)V

    goto :goto_0

    :pswitch_2
    sget-object v1, Llyiahf/vczjk/p46;->OooOOO0:Llyiahf/vczjk/p46;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ky;->OooO0o(Llyiahf/vczjk/qa4;)V

    goto :goto_0

    :pswitch_3
    sget-object v1, Llyiahf/vczjk/be0;->OooOOO:Llyiahf/vczjk/be0;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ky;->OooO0o(Llyiahf/vczjk/qa4;)V

    goto :goto_0

    :pswitch_4
    sget-object v1, Llyiahf/vczjk/be0;->OooOOO0:Llyiahf/vczjk/be0;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ky;->OooO0o(Llyiahf/vczjk/qa4;)V

    goto :goto_0

    :pswitch_5
    invoke-static {p1, p2, p3}, Llyiahf/vczjk/m80;->OoooOOo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/pca;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ky;->OooO0o(Llyiahf/vczjk/qa4;)V

    goto :goto_0

    :pswitch_6
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/ua4;->OooO0O0(Ljava/lang/String;)Llyiahf/vczjk/en9;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ky;->OooO0o(Llyiahf/vczjk/qa4;)V

    goto :goto_0

    :pswitch_7
    return-object v0

    :pswitch_8
    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/m80;->OoooOoo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/ky;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ky;->OooO0o(Llyiahf/vczjk/qa4;)V

    goto :goto_0

    :pswitch_9
    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/m80;->Ooooo00(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/f76;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ky;->OooO0o(Llyiahf/vczjk/qa4;)V

    goto :goto_0

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_9
        :pswitch_0
        :pswitch_8
        :pswitch_7
        :pswitch_0
        :pswitch_6
        :pswitch_5
        :pswitch_0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method

.method public final Ooooo00(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/f76;
    .locals 4

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Llyiahf/vczjk/f76;

    invoke-direct {v0, p3}, Llyiahf/vczjk/f76;-><init>(Llyiahf/vczjk/ua4;)V

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o()Ljava/lang/String;

    move-result-object v1

    :goto_0
    if-eqz v1, :cond_6

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v2

    if-nez v2, :cond_0

    sget-object v2, Llyiahf/vczjk/gc4;->OooOOO0:Llyiahf/vczjk/gc4;

    :cond_0
    invoke-virtual {v2}, Llyiahf/vczjk/gc4;->OooO0OO()I

    move-result v2

    const/4 v3, 0x1

    if-eq v2, v3, :cond_4

    const/4 v3, 0x3

    if-eq v2, v3, :cond_3

    const/4 v3, 0x6

    if-eq v2, v3, :cond_2

    const/4 v3, 0x7

    if-eq v2, v3, :cond_1

    packed-switch v2, :pswitch_data_0

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/m80;->OoooOoO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/qa4;

    move-result-object v2

    goto :goto_1

    :pswitch_0
    invoke-static {p1, p3}, Llyiahf/vczjk/m80;->OoooOOO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/qa4;

    move-result-object v2

    goto :goto_1

    :pswitch_1
    sget-object v2, Llyiahf/vczjk/p46;->OooOOO0:Llyiahf/vczjk/p46;

    goto :goto_1

    :pswitch_2
    sget-object v2, Llyiahf/vczjk/be0;->OooOOO:Llyiahf/vczjk/be0;

    goto :goto_1

    :pswitch_3
    sget-object v2, Llyiahf/vczjk/be0;->OooOOO0:Llyiahf/vczjk/be0;

    goto :goto_1

    :cond_1
    invoke-static {p1, p2, p3}, Llyiahf/vczjk/m80;->OoooOOo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/pca;

    move-result-object v2

    goto :goto_1

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/ua4;->OooO0O0(Ljava/lang/String;)Llyiahf/vczjk/en9;

    move-result-object v2

    goto :goto_1

    :cond_3
    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/m80;->OoooOoo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/ky;

    move-result-object v2

    goto :goto_1

    :cond_4
    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/m80;->Ooooo00(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/f76;

    move-result-object v2

    :goto_1
    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/f76;->OooO0o(Ljava/lang/String;Llyiahf/vczjk/qa4;)Llyiahf/vczjk/qa4;

    move-result-object v2

    if-eqz v2, :cond_5

    invoke-static {v1, p2}, Llyiahf/vczjk/m80;->OoooOo0(Ljava/lang/String;Llyiahf/vczjk/v72;)V

    :cond_5
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o()Ljava/lang/String;

    move-result-object v1

    goto :goto_0

    :cond_6
    return-object v0

    :pswitch_data_0
    .packed-switch 0x9
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final Ooooo0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/f76;
    .locals 4

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Llyiahf/vczjk/f76;

    invoke-direct {v0, p3}, Llyiahf/vczjk/f76;-><init>(Llyiahf/vczjk/ua4;)V

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->OoooOoo()Ljava/lang/String;

    move-result-object v1

    :goto_0
    if-eqz v1, :cond_6

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v2

    if-nez v2, :cond_0

    sget-object v2, Llyiahf/vczjk/gc4;->OooOOO0:Llyiahf/vczjk/gc4;

    :cond_0
    invoke-virtual {v2}, Llyiahf/vczjk/gc4;->OooO0OO()I

    move-result v2

    const/4 v3, 0x1

    if-eq v2, v3, :cond_4

    const/4 v3, 0x3

    if-eq v2, v3, :cond_3

    const/4 v3, 0x6

    if-eq v2, v3, :cond_2

    const/4 v3, 0x7

    if-eq v2, v3, :cond_1

    packed-switch v2, :pswitch_data_0

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/m80;->OoooOoO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/qa4;

    move-result-object v2

    goto :goto_1

    :pswitch_0
    invoke-static {p1, p3}, Llyiahf/vczjk/m80;->OoooOOO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/qa4;

    move-result-object v2

    goto :goto_1

    :pswitch_1
    sget-object v2, Llyiahf/vczjk/p46;->OooOOO0:Llyiahf/vczjk/p46;

    goto :goto_1

    :pswitch_2
    sget-object v2, Llyiahf/vczjk/be0;->OooOOO:Llyiahf/vczjk/be0;

    goto :goto_1

    :pswitch_3
    sget-object v2, Llyiahf/vczjk/be0;->OooOOO0:Llyiahf/vczjk/be0;

    goto :goto_1

    :cond_1
    invoke-static {p1, p2, p3}, Llyiahf/vczjk/m80;->OoooOOo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/pca;

    move-result-object v2

    goto :goto_1

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/ua4;->OooO0O0(Ljava/lang/String;)Llyiahf/vczjk/en9;

    move-result-object v2

    goto :goto_1

    :cond_3
    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/m80;->OoooOoo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/ky;

    move-result-object v2

    goto :goto_1

    :cond_4
    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/m80;->Ooooo00(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/f76;

    move-result-object v2

    :goto_1
    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/f76;->OooO0o(Ljava/lang/String;Llyiahf/vczjk/qa4;)Llyiahf/vczjk/qa4;

    move-result-object v2

    if-eqz v2, :cond_5

    invoke-static {v1, p2}, Llyiahf/vczjk/m80;->OoooOo0(Ljava/lang/String;Llyiahf/vczjk/v72;)V

    :cond_5
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o()Ljava/lang/String;

    move-result-object v1

    goto :goto_0

    :cond_6
    return-object v0

    :pswitch_data_0
    .packed-switch 0x9
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final OooooO0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ky;)V
    .locals 2

    invoke-virtual {p2}, Llyiahf/vczjk/v72;->o0Oo0oo()Llyiahf/vczjk/ua4;

    move-result-object v0

    :goto_0
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/gc4;->OooO0OO()I

    move-result v1

    packed-switch v1, :pswitch_data_0

    :pswitch_0
    invoke-virtual {p0, p1, p2, v0}, Llyiahf/vczjk/m80;->OoooOoO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/qa4;

    move-result-object v1

    invoke-virtual {p3, v1}, Llyiahf/vczjk/ky;->OooO0o(Llyiahf/vczjk/qa4;)V

    goto :goto_0

    :pswitch_1
    invoke-static {p1, v0}, Llyiahf/vczjk/m80;->OoooOOO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/qa4;

    move-result-object v1

    invoke-virtual {p3, v1}, Llyiahf/vczjk/ky;->OooO0o(Llyiahf/vczjk/qa4;)V

    goto :goto_0

    :pswitch_2
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/p46;->OooOOO0:Llyiahf/vczjk/p46;

    invoke-virtual {p3, v1}, Llyiahf/vczjk/ky;->OooO0o(Llyiahf/vczjk/qa4;)V

    goto :goto_0

    :pswitch_3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/be0;->OooOOO:Llyiahf/vczjk/be0;

    invoke-virtual {p3, v1}, Llyiahf/vczjk/ky;->OooO0o(Llyiahf/vczjk/qa4;)V

    goto :goto_0

    :pswitch_4
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/be0;->OooOOO0:Llyiahf/vczjk/be0;

    invoke-virtual {p3, v1}, Llyiahf/vczjk/ky;->OooO0o(Llyiahf/vczjk/qa4;)V

    goto :goto_0

    :pswitch_5
    invoke-static {p1, p2, v0}, Llyiahf/vczjk/m80;->OoooOOo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/pca;

    move-result-object v1

    invoke-virtual {p3, v1}, Llyiahf/vczjk/ky;->OooO0o(Llyiahf/vczjk/qa4;)V

    goto :goto_0

    :pswitch_6
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1}, Llyiahf/vczjk/ua4;->OooO0O0(Ljava/lang/String;)Llyiahf/vczjk/en9;

    move-result-object v1

    invoke-virtual {p3, v1}, Llyiahf/vczjk/ky;->OooO0o(Llyiahf/vczjk/qa4;)V

    goto :goto_0

    :pswitch_7
    return-void

    :pswitch_8
    invoke-virtual {p0, p1, p2, v0}, Llyiahf/vczjk/m80;->OoooOoo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/ky;

    move-result-object v1

    invoke-virtual {p3, v1}, Llyiahf/vczjk/ky;->OooO0o(Llyiahf/vczjk/qa4;)V

    goto :goto_0

    :pswitch_9
    invoke-virtual {p0, p1, p2, v0}, Llyiahf/vczjk/m80;->Ooooo00(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/f76;

    move-result-object v1

    invoke-virtual {p3, v1}, Llyiahf/vczjk/ky;->OooO0o(Llyiahf/vczjk/qa4;)V

    goto :goto_0

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_9
        :pswitch_0
        :pswitch_8
        :pswitch_7
        :pswitch_0
        :pswitch_6
        :pswitch_5
        :pswitch_0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method

.method public final OooooOO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/f76;)Llyiahf/vczjk/qa4;
    .locals 5

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o0O()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o()Ljava/lang/String;

    move-result-object v0

    goto :goto_0

    :cond_0
    sget-object v0, Llyiahf/vczjk/gc4;->OooOOo:Llyiahf/vczjk/gc4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/qa4;

    return-object p1

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->OoooOoo()Ljava/lang/String;

    move-result-object v0

    :goto_0
    if-eqz v0, :cond_b

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v1

    iget-object v2, p3, Llyiahf/vczjk/f76;->_children:Ljava/util/Map;

    invoke-interface {v2, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/qa4;

    if-eqz v2, :cond_3

    instance-of v3, v2, Llyiahf/vczjk/f76;

    if-eqz v3, :cond_2

    move-object v1, v2

    check-cast v1, Llyiahf/vczjk/f76;

    invoke-virtual {p0, p1, p2, v1}, Llyiahf/vczjk/m80;->OooooOO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/f76;)Llyiahf/vczjk/qa4;

    move-result-object v1

    if-eq v1, v2, :cond_a

    invoke-virtual {p3, v0, v1}, Llyiahf/vczjk/f76;->OooO0oo(Ljava/lang/String;Llyiahf/vczjk/qa4;)V

    goto/16 :goto_2

    :cond_2
    instance-of v3, v2, Llyiahf/vczjk/ky;

    if-eqz v3, :cond_3

    move-object v1, v2

    check-cast v1, Llyiahf/vczjk/ky;

    invoke-virtual {p0, p1, p2, v1}, Llyiahf/vczjk/m80;->OooooO0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ky;)V

    if-eq v1, v2, :cond_a

    invoke-virtual {p3, v0, v1}, Llyiahf/vczjk/f76;->OooO0oo(Ljava/lang/String;Llyiahf/vczjk/qa4;)V

    goto :goto_2

    :cond_3
    if-nez v1, :cond_4

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOO0:Llyiahf/vczjk/gc4;

    :cond_4
    invoke-virtual {p2}, Llyiahf/vczjk/v72;->o0Oo0oo()Llyiahf/vczjk/ua4;

    move-result-object v3

    invoke-virtual {v1}, Llyiahf/vczjk/gc4;->OooO0OO()I

    move-result v1

    const/4 v4, 0x1

    if-eq v1, v4, :cond_8

    const/4 v4, 0x3

    if-eq v1, v4, :cond_7

    const/4 v4, 0x6

    if-eq v1, v4, :cond_6

    const/4 v4, 0x7

    if-eq v1, v4, :cond_5

    packed-switch v1, :pswitch_data_0

    invoke-virtual {p0, p1, p2, v3}, Llyiahf/vczjk/m80;->OoooOoO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/qa4;

    move-result-object v1

    goto :goto_1

    :pswitch_0
    invoke-static {p1, v3}, Llyiahf/vczjk/m80;->OoooOOO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/qa4;

    move-result-object v1

    goto :goto_1

    :pswitch_1
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/p46;->OooOOO0:Llyiahf/vczjk/p46;

    goto :goto_1

    :pswitch_2
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/be0;->OooOOO:Llyiahf/vczjk/be0;

    goto :goto_1

    :pswitch_3
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/be0;->OooOOO0:Llyiahf/vczjk/be0;

    goto :goto_1

    :cond_5
    invoke-static {p1, p2, v3}, Llyiahf/vczjk/m80;->OoooOOo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/pca;

    move-result-object v1

    goto :goto_1

    :cond_6
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1}, Llyiahf/vczjk/ua4;->OooO0O0(Ljava/lang/String;)Llyiahf/vczjk/en9;

    move-result-object v1

    goto :goto_1

    :cond_7
    invoke-virtual {p0, p1, p2, v3}, Llyiahf/vczjk/m80;->OoooOoo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/ky;

    move-result-object v1

    goto :goto_1

    :cond_8
    invoke-virtual {p0, p1, p2, v3}, Llyiahf/vczjk/m80;->Ooooo00(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/f76;

    move-result-object v1

    :goto_1
    if-eqz v2, :cond_9

    invoke-static {v0, p2}, Llyiahf/vczjk/m80;->OoooOo0(Ljava/lang/String;Llyiahf/vczjk/v72;)V

    :cond_9
    invoke-virtual {p3, v0, v1}, Llyiahf/vczjk/f76;->OooO0oo(Ljava/lang/String;Llyiahf/vczjk/qa4;)V

    :cond_a
    :goto_2
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o()Ljava/lang/String;

    move-result-object v0

    goto/16 :goto_0

    :cond_b
    return-object p3

    :pswitch_data_0
    .packed-switch 0x9
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
