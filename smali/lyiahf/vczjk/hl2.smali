.class public abstract Llyiahf/vczjk/hl2;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/h1a;

.field public static final OooO0O0:Llyiahf/vczjk/h1a;

.field public static final OooO0OO:Llyiahf/vczjk/h1a;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    new-instance v0, Llyiahf/vczjk/cu1;

    const v1, 0x3ecccccd    # 0.4f

    const/4 v2, 0x0

    const v3, 0x3f19999a    # 0.6f

    const/high16 v4, 0x3f800000    # 1.0f

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/cu1;-><init>(FFFF)V

    new-instance v1, Llyiahf/vczjk/h1a;

    sget-object v2, Llyiahf/vczjk/jk2;->OooO00o:Llyiahf/vczjk/cu1;

    const/16 v3, 0x78

    const/4 v4, 0x2

    invoke-direct {v1, v3, v2, v4}, Llyiahf/vczjk/h1a;-><init>(ILlyiahf/vczjk/ik2;I)V

    sput-object v1, Llyiahf/vczjk/hl2;->OooO00o:Llyiahf/vczjk/h1a;

    new-instance v1, Llyiahf/vczjk/h1a;

    const/16 v2, 0x96

    invoke-direct {v1, v2, v0, v4}, Llyiahf/vczjk/h1a;-><init>(ILlyiahf/vczjk/ik2;I)V

    sput-object v1, Llyiahf/vczjk/hl2;->OooO0O0:Llyiahf/vczjk/h1a;

    new-instance v1, Llyiahf/vczjk/h1a;

    invoke-direct {v1, v3, v0, v4}, Llyiahf/vczjk/h1a;-><init>(ILlyiahf/vczjk/ik2;I)V

    sput-object v1, Llyiahf/vczjk/hl2;->OooO0OO:Llyiahf/vczjk/h1a;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/gi;FLlyiahf/vczjk/j24;Llyiahf/vczjk/j24;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 7

    const/4 v0, 0x0

    if-eqz p3, :cond_4

    instance-of p2, p3, Llyiahf/vczjk/q37;

    sget-object v1, Llyiahf/vczjk/hl2;->OooO00o:Llyiahf/vczjk/h1a;

    if-eqz p2, :cond_0

    :goto_0
    move-object v0, v1

    goto :goto_1

    :cond_0
    instance-of p2, p3, Llyiahf/vczjk/mf2;

    if-eqz p2, :cond_1

    goto :goto_0

    :cond_1
    instance-of p2, p3, Llyiahf/vczjk/wo3;

    if-eqz p2, :cond_2

    goto :goto_0

    :cond_2
    instance-of p2, p3, Llyiahf/vczjk/g83;

    if-eqz p2, :cond_3

    goto :goto_0

    :cond_3
    :goto_1
    move-object v3, v0

    goto :goto_3

    :cond_4
    if-eqz p2, :cond_3

    instance-of p3, p2, Llyiahf/vczjk/q37;

    sget-object v1, Llyiahf/vczjk/hl2;->OooO0O0:Llyiahf/vczjk/h1a;

    if-eqz p3, :cond_5

    :goto_2
    goto :goto_0

    :cond_5
    instance-of p3, p2, Llyiahf/vczjk/mf2;

    if-eqz p3, :cond_6

    goto :goto_2

    :cond_6
    instance-of p3, p2, Llyiahf/vczjk/wo3;

    if-eqz p3, :cond_7

    sget-object v0, Llyiahf/vczjk/hl2;->OooO0OO:Llyiahf/vczjk/h1a;

    goto :goto_1

    :cond_7
    instance-of p2, p2, Llyiahf/vczjk/g83;

    if-eqz p2, :cond_3

    goto :goto_2

    :goto_3
    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-eqz v3, :cond_8

    new-instance v2, Llyiahf/vczjk/wd2;

    invoke-direct {v2, p1}, Llyiahf/vczjk/wd2;-><init>(F)V

    const/16 v6, 0xc

    const/4 v4, 0x0

    move-object v1, p0

    move-object v5, p4

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/gi;->OooO0O0(Llyiahf/vczjk/gi;Ljava/lang/Object;Llyiahf/vczjk/wl;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;I)Ljava/lang/Object;

    move-result-object p0

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p0, p1, :cond_9

    return-object p0

    :cond_8
    move-object v1, p0

    move-object v5, p4

    new-instance p0, Llyiahf/vczjk/wd2;

    invoke-direct {p0, p1}, Llyiahf/vczjk/wd2;-><init>(F)V

    invoke-virtual {v1, p0, v5}, Llyiahf/vczjk/gi;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p0

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p0, p1, :cond_9

    return-object p0

    :cond_9
    return-object p2
.end method
