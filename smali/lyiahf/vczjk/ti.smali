.class public abstract Llyiahf/vczjk/ti;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/wz8;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    const/4 v0, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x7

    invoke-static {v1, v1, v0, v2}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/ti;->OooO00o:Llyiahf/vczjk/wz8;

    sget-object v0, Llyiahf/vczjk/hka;->OooO00o:Ljava/lang/Object;

    new-instance v0, Llyiahf/vczjk/wd2;

    const v2, 0x3dcccccd    # 0.1f

    invoke-direct {v0, v2}, Llyiahf/vczjk/wd2;-><init>(F)V

    const/4 v2, 0x3

    invoke-static {v1, v1, v0, v2}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    const/high16 v0, 0x3f000000    # 0.5f

    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    return-void
.end method

.method public static final OooO00o(FLlyiahf/vczjk/p13;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/p29;
    .locals 8

    and-int/lit8 p4, p4, 0x4

    if-eqz p4, :cond_0

    const-string p4, "DpAnimation"

    :goto_0
    move-object v4, p4

    goto :goto_1

    :cond_0
    const-string p4, "Icon size"

    goto :goto_0

    :goto_1
    new-instance v0, Llyiahf/vczjk/wd2;

    invoke-direct {v0, p0}, Llyiahf/vczjk/wd2;-><init>(F)V

    sget-object v1, Llyiahf/vczjk/gda;->OooO0OO:Llyiahf/vczjk/n1a;

    shl-int/lit8 p0, p3, 0x3

    and-int/lit16 p0, p0, 0x380

    shl-int/lit8 p3, p3, 0x6

    const p4, 0xe000

    and-int/2addr p3, p4

    or-int v6, p0, p3

    const/16 v7, 0x8

    const/4 v3, 0x0

    move-object v2, p1

    move-object v5, p2

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/ti;->OooO0OO(Ljava/lang/Object;Llyiahf/vczjk/m1a;Llyiahf/vczjk/wl;Ljava/lang/Float;Ljava/lang/String;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/p29;

    move-result-object p0

    return-object p0
.end method

.method public static final OooO0O0(FLlyiahf/vczjk/p13;Ljava/lang/String;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/p29;
    .locals 10

    and-int/lit8 v0, p5, 0x2

    sget-object v1, Llyiahf/vczjk/ti;->OooO00o:Llyiahf/vczjk/wz8;

    if-eqz v0, :cond_0

    move-object p1, v1

    :cond_0
    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_1

    const-string p2, "FloatAnimation"

    :cond_1
    move-object v6, p2

    const p2, 0x3c23d70a    # 0.01f

    const/4 p5, 0x3

    const/4 v0, 0x0

    if-ne p1, v1, :cond_4

    move-object p1, p3

    check-cast p1, Llyiahf/vczjk/zf1;

    const v1, 0x4316aad7

    invoke-virtual {p1, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v1

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v1, :cond_2

    sget-object v1, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v2, v1, :cond_3

    :cond_2
    invoke-static {p2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    const/4 v2, 0x0

    invoke-static {v2, v2, v1, p5}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object v2

    invoke-virtual {p1, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    move-object v1, v2

    check-cast v1, Llyiahf/vczjk/wz8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v4, v1

    goto :goto_0

    :cond_4
    move-object v1, p3

    check-cast v1, Llyiahf/vczjk/zf1;

    const v2, 0x4318583d

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v4, p1

    :goto_0
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/gda;->OooO00o:Llyiahf/vczjk/n1a;

    invoke-static {p2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v5

    shl-int/lit8 p0, p4, 0x3

    const p1, 0xe000

    and-int v8, p0, p1

    const/4 v9, 0x0

    move-object v7, p3

    invoke-static/range {v2 .. v9}, Llyiahf/vczjk/ti;->OooO0OO(Ljava/lang/Object;Llyiahf/vczjk/m1a;Llyiahf/vczjk/wl;Ljava/lang/Float;Ljava/lang/String;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/p29;

    move-result-object p0

    return-object p0
.end method

.method public static final OooO0OO(Ljava/lang/Object;Llyiahf/vczjk/m1a;Llyiahf/vczjk/wl;Ljava/lang/Float;Ljava/lang/String;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/p29;
    .locals 8

    sget-object p6, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    and-int/lit8 p7, p7, 0x8

    const/4 v0, 0x0

    if-eqz p7, :cond_0

    move-object p3, v0

    :cond_0
    check-cast p5, Llyiahf/vczjk/zf1;

    invoke-virtual {p5}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p7

    if-ne p7, p6, :cond_1

    invoke-static {v0}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p7

    invoke-virtual {p5, p7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    check-cast p7, Llyiahf/vczjk/qs5;

    invoke-virtual {p5}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-ne v1, p6, :cond_2

    new-instance v1, Llyiahf/vczjk/gi;

    invoke-direct {v1, p0, p1, p3, p4}, Llyiahf/vczjk/gi;-><init>(Ljava/lang/Object;Llyiahf/vczjk/m1a;Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p5, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_2
    move-object v4, v1

    check-cast v4, Llyiahf/vczjk/gi;

    invoke-static {v0, p5}, Landroidx/compose/runtime/OooO0o;->OooOO0O(Ljava/lang/Object;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v6

    if-eqz p3, :cond_3

    instance-of p1, p2, Llyiahf/vczjk/wz8;

    if-eqz p1, :cond_3

    move-object p1, p2

    check-cast p1, Llyiahf/vczjk/wz8;

    iget-object p4, p1, Llyiahf/vczjk/wz8;->OooO0OO:Ljava/lang/Object;

    invoke-static {p4, p3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p4

    if-nez p4, :cond_3

    new-instance p2, Llyiahf/vczjk/wz8;

    iget p4, p1, Llyiahf/vczjk/wz8;->OooO00o:F

    iget p1, p1, Llyiahf/vczjk/wz8;->OooO0O0:F

    invoke-direct {p2, p4, p1, p3}, Llyiahf/vczjk/wz8;-><init>(FFLjava/lang/Object;)V

    :cond_3
    invoke-static {p2, p5}, Landroidx/compose/runtime/OooO0o;->OooOO0O(Ljava/lang/Object;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v5

    invoke-virtual {p5}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p1

    if-ne p1, p6, :cond_4

    const/4 p1, -0x1

    const/4 p2, 0x6

    invoke-static {p1, p2, v0}, Llyiahf/vczjk/tg0;->OooO0o0(IILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jj0;

    move-result-object p1

    invoke-virtual {p5, p1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4
    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/rs0;

    invoke-virtual {p5, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p1

    invoke-virtual {p5, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p2

    or-int/2addr p1, p2

    invoke-virtual {p5}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p2

    if-nez p1, :cond_5

    if-ne p2, p6, :cond_6

    :cond_5
    new-instance p2, Llyiahf/vczjk/qi;

    invoke-direct {p2, v3, p0}, Llyiahf/vczjk/qi;-><init>(Llyiahf/vczjk/rs0;Ljava/lang/Object;)V

    invoke-virtual {p5, p2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast p2, Llyiahf/vczjk/le3;

    invoke-static {p2, p5}, Llyiahf/vczjk/c6a;->OooOo00(Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;)V

    invoke-virtual {p5, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p0

    invoke-virtual {p5, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p1

    or-int/2addr p0, p1

    invoke-virtual {p5, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p1

    or-int/2addr p0, p1

    invoke-virtual {p5, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p1

    or-int/2addr p0, p1

    invoke-virtual {p5}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p1

    if-nez p0, :cond_7

    if-ne p1, p6, :cond_8

    :cond_7
    new-instance v2, Llyiahf/vczjk/si;

    const/4 v7, 0x0

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/si;-><init>(Llyiahf/vczjk/rs0;Llyiahf/vczjk/gi;Llyiahf/vczjk/p29;Llyiahf/vczjk/p29;Llyiahf/vczjk/yo1;)V

    invoke-virtual {p5, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object p1, v2

    :cond_8
    check-cast p1, Llyiahf/vczjk/ze3;

    invoke-static {v3, p5, p1}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-interface {p7}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/p29;

    if-nez p0, :cond_9

    iget-object p0, v4, Llyiahf/vczjk/gi;->OooO0OO:Llyiahf/vczjk/xl;

    :cond_9
    return-object p0
.end method
