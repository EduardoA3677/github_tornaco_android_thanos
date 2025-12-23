.class public final Llyiahf/vczjk/h56;
.super Llyiahf/vczjk/a59;
.source "SourceFile"


# static fields
.field public static final OooOOOO:Llyiahf/vczjk/h56;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/h56;

    const-class v1, Ljava/math/BigDecimal;

    invoke-direct {v0, v1}, Llyiahf/vczjk/m49;-><init>(Ljava/lang/Class;)V

    sput-object v0, Llyiahf/vczjk/h56;->OooOOOO:Llyiahf/vczjk/h56;

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 4

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0OoOo0()I

    move-result v0

    const/4 v1, 0x3

    if-eq v0, v1, :cond_4

    const/4 v1, 0x6

    const/4 v2, 0x0

    if-eq v0, v1, :cond_2

    const/4 v1, 0x7

    if-eq v0, v1, :cond_1

    const/16 v1, 0x8

    if-ne v0, v1, :cond_0

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o000000o(Ljava/lang/Class;Llyiahf/vczjk/eb4;)V

    throw v2

    :cond_1
    :goto_0
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o00oO0o()Ljava/math/BigDecimal;

    move-result-object p1

    return-object p1

    :cond_2
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p2}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object p2

    invoke-static {p2}, Llyiahf/vczjk/m49;->OooOoO(Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/m49;->Oooo0oO(Ljava/lang/String;Llyiahf/vczjk/v72;)V

    return-object v2

    :cond_3
    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/m49;->Oooo(Ljava/lang/String;Llyiahf/vczjk/v72;)V

    :try_start_0
    new-instance v0, Ljava/math/BigDecimal;

    invoke-direct {v0, p2}, Ljava/math/BigDecimal;-><init>(Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    return-object v0

    :catch_0
    iget-object v0, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/Object;

    const-string v3, "not a valid representation"

    invoke-virtual {p1, v0, p2, v3, v1}, Llyiahf/vczjk/v72;->o0000Ooo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v2

    :cond_4
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->OooOo0O(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/math/BigDecimal;

    return-object p1
.end method

.method public final OooOO0(Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 0

    sget-object p1, Ljava/math/BigDecimal;->ZERO:Ljava/math/BigDecimal;

    return-object p1
.end method
