.class public abstract Llyiahf/vczjk/hr4;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/oq4;


# direct methods
.method static constructor <clinit>()V
    .locals 20

    new-instance v5, Llyiahf/vczjk/fr4;

    const/4 v0, 0x0

    invoke-direct {v5, v0}, Llyiahf/vczjk/fr4;-><init>(I)V

    sget-object v12, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    sget-object v17, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    invoke-static {}, Llyiahf/vczjk/vc6;->OooO0o0()Llyiahf/vczjk/i62;

    move-result-object v9

    sget-object v0, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooO0oO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/to1;

    move-result-object v8

    new-instance v0, Llyiahf/vczjk/oq4;

    sget-object v11, Llyiahf/vczjk/mo2;->Oooo00O:Llyiahf/vczjk/mo2;

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v10, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    invoke-direct/range {v0 .. v19}, Llyiahf/vczjk/oq4;-><init>(Llyiahf/vczjk/rq4;IZFLlyiahf/vczjk/mf5;FZLlyiahf/vczjk/xr1;Llyiahf/vczjk/f62;ILlyiahf/vczjk/oe3;Ljava/util/List;IIIZLlyiahf/vczjk/nf6;II)V

    sput-object v0, Llyiahf/vczjk/hr4;->OooO00o:Llyiahf/vczjk/oq4;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/er4;
    .locals 7

    const/4 v0, 0x0

    new-array v1, v0, [Ljava/lang/Object;

    sget-object v2, Llyiahf/vczjk/er4;->OooOo0o:Llyiahf/vczjk/era;

    move-object v3, p0

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v3

    move-object v4, p0

    check-cast v4, Llyiahf/vczjk/zf1;

    invoke-virtual {v4, v0}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v0

    or-int/2addr v0, v3

    move-object v4, p0

    check-cast v4, Llyiahf/vczjk/zf1;

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p0

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne p0, v0, :cond_1

    :cond_0
    new-instance p0, Llyiahf/vczjk/gr4;

    invoke-direct {p0}, Llyiahf/vczjk/gr4;-><init>()V

    invoke-virtual {v4, p0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    move-object v3, p0

    check-cast v3, Llyiahf/vczjk/le3;

    const/4 v5, 0x0

    const/4 v6, 0x4

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/ht6;->OooOo0o([Ljava/lang/Object;Llyiahf/vczjk/era;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/er4;

    return-object p0
.end method
