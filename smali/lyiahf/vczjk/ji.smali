.class public abstract Llyiahf/vczjk/ji;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/era;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    const-string v0, "x"

    const-string v1, "y"

    const-string v2, "k"

    filled-new-array {v2, v0, v1}, [Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/era;->OoooO0([Ljava/lang/String;)Llyiahf/vczjk/era;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/ji;->OooO00o:Llyiahf/vczjk/era;

    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/rc4;Llyiahf/vczjk/z75;)Llyiahf/vczjk/sw7;
    .locals 9

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {p0}, Llyiahf/vczjk/rc4;->OoooOoo()I

    move-result v1

    const/4 v2, 0x1

    if-ne v1, v2, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/rc4;->OooO0Oo()V

    :goto_0
    invoke-virtual {p0}, Llyiahf/vczjk/rc4;->OooOoOO()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/rc4;->OoooOoo()I

    move-result v1

    const/4 v3, 0x3

    if-ne v1, v3, :cond_0

    move v7, v2

    goto :goto_1

    :cond_0
    const/4 v1, 0x0

    move v7, v1

    :goto_1
    invoke-static {}, Llyiahf/vczjk/qba;->OooO0OO()F

    move-result v5

    sget-object v6, Llyiahf/vczjk/sp3;->OooOOo:Llyiahf/vczjk/sp3;

    const/4 v8, 0x0

    move-object v3, p0

    move-object v4, p1

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/rj4;->OooO0O0(Llyiahf/vczjk/rb4;Llyiahf/vczjk/z75;FLlyiahf/vczjk/uca;ZZ)Llyiahf/vczjk/pj4;

    move-result-object p0

    new-instance p1, Llyiahf/vczjk/eq6;

    invoke-direct {p1, v4, p0}, Llyiahf/vczjk/eq6;-><init>(Llyiahf/vczjk/z75;Llyiahf/vczjk/pj4;)V

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move-object p0, v3

    move-object p1, v4

    goto :goto_0

    :cond_1
    move-object v3, p0

    invoke-virtual {v3}, Llyiahf/vczjk/rc4;->OooOOOO()V

    invoke-static {v0}, Llyiahf/vczjk/sj4;->OooO0O0(Ljava/util/ArrayList;)V

    goto :goto_2

    :cond_2
    move-object v3, p0

    new-instance p0, Llyiahf/vczjk/pj4;

    invoke-static {}, Llyiahf/vczjk/qba;->OooO0OO()F

    move-result p1

    invoke-static {v3, p1}, Llyiahf/vczjk/sc4;->OooO0O0(Llyiahf/vczjk/rb4;F)Landroid/graphics/PointF;

    move-result-object p1

    invoke-direct {p0, p1}, Llyiahf/vczjk/pj4;-><init>(Ljava/lang/Object;)V

    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :goto_2
    new-instance p0, Llyiahf/vczjk/sw7;

    const/4 p1, 0x3

    invoke-direct {p0, v0, p1}, Llyiahf/vczjk/sw7;-><init>(Ljava/lang/Object;I)V

    return-object p0
.end method

.method public static OooO0O0(Llyiahf/vczjk/rc4;Llyiahf/vczjk/z75;)Llyiahf/vczjk/pi;
    .locals 8

    invoke-virtual {p0}, Llyiahf/vczjk/rc4;->OooO0oO()V

    const/4 v0, 0x0

    const/4 v1, 0x0

    move-object v2, v0

    move v3, v1

    move-object v1, v2

    :goto_0
    invoke-virtual {p0}, Llyiahf/vczjk/rc4;->OoooOoo()I

    move-result v4

    const/4 v5, 0x4

    if-eq v4, v5, :cond_5

    sget-object v4, Llyiahf/vczjk/ji;->OooO00o:Llyiahf/vczjk/era;

    invoke-virtual {p0, v4}, Llyiahf/vczjk/rc4;->o0OoOo0(Llyiahf/vczjk/era;)I

    move-result v4

    if-eqz v4, :cond_4

    const/4 v5, 0x6

    const/4 v6, 0x1

    if-eq v4, v6, :cond_2

    const/4 v7, 0x2

    if-eq v4, v7, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/rc4;->o00oO0o()V

    invoke-virtual {p0}, Llyiahf/vczjk/rc4;->o0ooOO0()V

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/rc4;->OoooOoo()I

    move-result v4

    if-ne v4, v5, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/rc4;->o0ooOO0()V

    :goto_1
    move v3, v6

    goto :goto_0

    :cond_1
    invoke-static {p0, p1, v6}, Llyiahf/vczjk/sb;->Oooo0o(Llyiahf/vczjk/rb4;Llyiahf/vczjk/z75;Z)Llyiahf/vczjk/ii;

    move-result-object v2

    goto :goto_0

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/rc4;->OoooOoo()I

    move-result v4

    if-ne v4, v5, :cond_3

    invoke-virtual {p0}, Llyiahf/vczjk/rc4;->o0ooOO0()V

    goto :goto_1

    :cond_3
    invoke-static {p0, p1, v6}, Llyiahf/vczjk/sb;->Oooo0o(Llyiahf/vczjk/rb4;Llyiahf/vczjk/z75;Z)Llyiahf/vczjk/ii;

    move-result-object v1

    goto :goto_0

    :cond_4
    invoke-static {p0, p1}, Llyiahf/vczjk/ji;->OooO00o(Llyiahf/vczjk/rc4;Llyiahf/vczjk/z75;)Llyiahf/vczjk/sw7;

    move-result-object v0

    goto :goto_0

    :cond_5
    invoke-virtual {p0}, Llyiahf/vczjk/rc4;->OooOo()V

    if-eqz v3, :cond_6

    const-string p0, "Lottie doesn\'t support expressions."

    invoke-virtual {p1, p0}, Llyiahf/vczjk/z75;->OooO00o(Ljava/lang/String;)V

    :cond_6
    if-eqz v0, :cond_7

    return-object v0

    :cond_7
    new-instance p0, Llyiahf/vczjk/ki;

    invoke-direct {p0, v1, v2}, Llyiahf/vczjk/ki;-><init>(Llyiahf/vczjk/ii;Llyiahf/vczjk/ii;)V

    return-object p0
.end method
