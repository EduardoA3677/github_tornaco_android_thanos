.class public final Llyiahf/vczjk/gp9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOOO0:Llyiahf/vczjk/bf3;

.field public final synthetic OooOOOO:Llyiahf/vczjk/le3;

.field public final synthetic OooOOOo:Llyiahf/vczjk/hb8;

.field public final synthetic OooOOo:Llyiahf/vczjk/ze3;

.field public final synthetic OooOOo0:Llyiahf/vczjk/gt2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bf3;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/hb8;Llyiahf/vczjk/gt2;Llyiahf/vczjk/ze3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/gp9;->OooOOO0:Llyiahf/vczjk/bf3;

    iput-object p2, p0, Llyiahf/vczjk/gp9;->OooOOO:Llyiahf/vczjk/a91;

    iput-object p3, p0, Llyiahf/vczjk/gp9;->OooOOOO:Llyiahf/vczjk/le3;

    iput-object p4, p0, Llyiahf/vczjk/gp9;->OooOOOo:Llyiahf/vczjk/hb8;

    iput-object p5, p0, Llyiahf/vczjk/gp9;->OooOOo0:Llyiahf/vczjk/gt2;

    iput-object p6, p0, Llyiahf/vczjk/gp9;->OooOOo:Llyiahf/vczjk/ze3;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    move-object v6, p1

    check-cast v6, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p1

    and-int/lit8 p1, p1, 0x3

    const/4 p2, 0x2

    if-ne p1, p2, :cond_1

    move-object p1, v6

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result p2

    if-nez p2, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    new-instance p1, Llyiahf/vczjk/d4;

    iget-object p2, p0, Llyiahf/vczjk/gp9;->OooOOo:Llyiahf/vczjk/ze3;

    const/4 v0, 0x2

    invoke-direct {p1, p2, v0}, Llyiahf/vczjk/d4;-><init>(Llyiahf/vczjk/ze3;I)V

    const p2, -0x21ccc552

    invoke-static {p2, p1, v6}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v0

    iget-object v5, p0, Llyiahf/vczjk/gp9;->OooOOo0:Llyiahf/vczjk/gt2;

    iget-object v1, p0, Llyiahf/vczjk/gp9;->OooOOO0:Llyiahf/vczjk/bf3;

    iget-object v2, p0, Llyiahf/vczjk/gp9;->OooOOO:Llyiahf/vczjk/a91;

    iget-object v3, p0, Llyiahf/vczjk/gp9;->OooOOOO:Llyiahf/vczjk/le3;

    iget-object v4, p0, Llyiahf/vczjk/gp9;->OooOOOo:Llyiahf/vczjk/hb8;

    const/4 v7, 0x6

    const/4 v8, 0x0

    invoke-static/range {v0 .. v8}, Llyiahf/vczjk/xr6;->OooO0o(Llyiahf/vczjk/a91;Llyiahf/vczjk/bf3;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/hb8;Llyiahf/vczjk/jx9;Llyiahf/vczjk/rf1;II)V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
