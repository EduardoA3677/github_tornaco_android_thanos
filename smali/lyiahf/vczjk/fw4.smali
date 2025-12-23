.class public abstract Llyiahf/vczjk/fw4;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/sv4;


# direct methods
.method static constructor <clinit>()V
    .locals 20

    new-instance v5, Llyiahf/vczjk/fr4;

    const/4 v0, 0x1

    invoke-direct {v5, v0}, Llyiahf/vczjk/fr4;-><init>(I)V

    sget-object v12, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    sget-object v17, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    sget-object v0, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooO0oO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/to1;

    move-result-object v8

    invoke-static {}, Llyiahf/vczjk/vc6;->OooO0o0()Llyiahf/vczjk/i62;

    move-result-object v9

    const/16 v0, 0xf

    const/4 v1, 0x0

    invoke-static {v1, v1, v0}, Llyiahf/vczjk/uk1;->OooO0O0(III)J

    move-result-wide v10

    new-instance v0, Llyiahf/vczjk/sv4;

    const/16 v16, 0x0

    const/16 v18, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/16 v19, 0x0

    invoke-direct/range {v0 .. v19}, Llyiahf/vczjk/sv4;-><init>(Llyiahf/vczjk/tv4;IZFLlyiahf/vczjk/mf5;FZLlyiahf/vczjk/xr1;Llyiahf/vczjk/f62;JLjava/util/List;IIIZLlyiahf/vczjk/nf6;II)V

    sput-object v0, Llyiahf/vczjk/fw4;->OooO00o:Llyiahf/vczjk/sv4;

    return-void
.end method

.method public static final OooO00o(IILlyiahf/vczjk/rf1;)Llyiahf/vczjk/dw4;
    .locals 7

    and-int/lit8 p1, p1, 0x1

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    move p0, v0

    :cond_0
    new-array v1, v0, [Ljava/lang/Object;

    sget-object v2, Llyiahf/vczjk/dw4;->OooOo0o:Llyiahf/vczjk/era;

    move-object p1, p2

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1, p0}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result p1

    move-object v3, p2

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v0

    or-int/2addr p1, v0

    move-object v4, p2

    check-cast v4, Llyiahf/vczjk/zf1;

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p2

    if-nez p1, :cond_1

    sget-object p1, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne p2, p1, :cond_2

    :cond_1
    new-instance p2, Llyiahf/vczjk/ew4;

    invoke-direct {p2, p0}, Llyiahf/vczjk/ew4;-><init>(I)V

    invoke-virtual {v4, p2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_2
    move-object v3, p2

    check-cast v3, Llyiahf/vczjk/le3;

    const/4 v5, 0x0

    const/4 v6, 0x4

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/ht6;->OooOo0o([Ljava/lang/Object;Llyiahf/vczjk/era;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/dw4;

    return-object p0
.end method
