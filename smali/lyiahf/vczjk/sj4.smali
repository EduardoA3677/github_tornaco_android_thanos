.class public abstract Llyiahf/vczjk/sj4;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/era;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const-string v0, "k"

    filled-new-array {v0}, [Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/era;->OoooO0([Ljava/lang/String;)Llyiahf/vczjk/era;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/sj4;->OooO00o:Llyiahf/vczjk/era;

    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/rb4;Llyiahf/vczjk/z75;FLlyiahf/vczjk/uca;Z)Ljava/util/ArrayList;
    .locals 9

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {p0}, Llyiahf/vczjk/rb4;->OoooOoo()I

    move-result v1

    const/4 v2, 0x6

    if-ne v1, v2, :cond_0

    const-string p0, "Lottie doesn\'t support expressions."

    invoke-virtual {p1, p0}, Llyiahf/vczjk/z75;->OooO00o(Ljava/lang/String;)V

    return-object v0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/rb4;->OooO0oO()V

    :goto_0
    invoke-virtual {p0}, Llyiahf/vczjk/rb4;->OooOoOO()Z

    move-result v1

    if-eqz v1, :cond_5

    sget-object v1, Llyiahf/vczjk/sj4;->OooO00o:Llyiahf/vczjk/era;

    invoke-virtual {p0, v1}, Llyiahf/vczjk/rb4;->o0OoOo0(Llyiahf/vczjk/era;)I

    move-result v1

    if-eqz v1, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/rb4;->o0ooOO0()V

    goto :goto_0

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/rb4;->OoooOoo()I

    move-result v1

    const/4 v2, 0x1

    if-ne v1, v2, :cond_4

    invoke-virtual {p0}, Llyiahf/vczjk/rb4;->OooO0Oo()V

    invoke-virtual {p0}, Llyiahf/vczjk/rb4;->OoooOoo()I

    move-result v1

    const/4 v2, 0x7

    if-ne v1, v2, :cond_2

    const/4 v7, 0x0

    move-object v3, p0

    move-object v4, p1

    move v5, p2

    move-object v6, p3

    move v8, p4

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/rj4;->OooO0O0(Llyiahf/vczjk/rb4;Llyiahf/vczjk/z75;FLlyiahf/vczjk/uca;ZZ)Llyiahf/vczjk/pj4;

    move-result-object p0

    move-object v1, v3

    move-object v2, v4

    move v3, v5

    move-object v4, v6

    move v6, v8

    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_2
    move-object v1, p0

    move-object v2, p1

    move v3, p2

    move-object v4, p3

    move v6, p4

    :goto_1
    invoke-virtual {v1}, Llyiahf/vczjk/rb4;->OooOoOO()Z

    move-result p0

    if-eqz p0, :cond_3

    const/4 v5, 0x1

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/rj4;->OooO0O0(Llyiahf/vczjk/rb4;Llyiahf/vczjk/z75;FLlyiahf/vczjk/uca;ZZ)Llyiahf/vczjk/pj4;

    move-result-object p0

    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_3
    :goto_2
    invoke-virtual {v1}, Llyiahf/vczjk/rb4;->OooOOOO()V

    move-object p0, v1

    move-object p1, v2

    move p2, v3

    move-object p3, v4

    move p4, v6

    goto :goto_0

    :cond_4
    move-object v1, p0

    move-object v2, p1

    move v3, p2

    move-object v4, p3

    move v6, p4

    const/4 v5, 0x0

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/rj4;->OooO0O0(Llyiahf/vczjk/rb4;Llyiahf/vczjk/z75;FLlyiahf/vczjk/uca;ZZ)Llyiahf/vczjk/pj4;

    move-result-object p0

    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move-object p0, v1

    goto :goto_0

    :cond_5
    move-object v1, p0

    invoke-virtual {v1}, Llyiahf/vczjk/rb4;->OooOo()V

    invoke-static {v0}, Llyiahf/vczjk/sj4;->OooO0O0(Ljava/util/ArrayList;)V

    return-object v0
.end method

.method public static OooO0O0(Ljava/util/ArrayList;)V
    .locals 5

    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    move-result v0

    const/4 v1, 0x0

    :cond_0
    :goto_0
    const/4 v2, 0x1

    add-int/lit8 v3, v0, -0x1

    if-ge v1, v3, :cond_1

    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/pj4;

    add-int/lit8 v1, v1, 0x1

    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/pj4;

    iget v4, v3, Llyiahf/vczjk/pj4;->OooO0oO:F

    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v4

    iput-object v4, v2, Llyiahf/vczjk/pj4;->OooO0oo:Ljava/lang/Float;

    iget-object v4, v2, Llyiahf/vczjk/pj4;->OooO0OO:Ljava/lang/Object;

    if-nez v4, :cond_0

    iget-object v3, v3, Llyiahf/vczjk/pj4;->OooO0O0:Ljava/lang/Object;

    if-eqz v3, :cond_0

    iput-object v3, v2, Llyiahf/vczjk/pj4;->OooO0OO:Ljava/lang/Object;

    instance-of v3, v2, Llyiahf/vczjk/eq6;

    if-eqz v3, :cond_0

    check-cast v2, Llyiahf/vczjk/eq6;

    invoke-virtual {v2}, Llyiahf/vczjk/eq6;->OooO0Oo()V

    goto :goto_0

    :cond_1
    invoke-virtual {p0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/pj4;

    iget-object v1, v0, Llyiahf/vczjk/pj4;->OooO0O0:Ljava/lang/Object;

    if-eqz v1, :cond_2

    iget-object v1, v0, Llyiahf/vczjk/pj4;->OooO0OO:Ljava/lang/Object;

    if-nez v1, :cond_3

    :cond_2
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    move-result v1

    if-le v1, v2, :cond_3

    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    :cond_3
    return-void
.end method
