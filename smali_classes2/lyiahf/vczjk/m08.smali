.class public final synthetic Llyiahf/vczjk/m08;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/String;

.field public final synthetic OooOOO0:Ljava/lang/String;

.field public final synthetic OooOOOO:Llyiahf/vczjk/hb8;

.field public final synthetic OooOOOo:Llyiahf/vczjk/i48;

.field public final synthetic OooOOo:Landroid/content/Context;

.field public final synthetic OooOOo0:Llyiahf/vczjk/wa5;

.field public final synthetic OooOOoo:Llyiahf/vczjk/qs5;

.field public final synthetic OooOo0:Llyiahf/vczjk/cp8;

.field public final synthetic OooOo00:Llyiahf/vczjk/qs5;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/hb8;Llyiahf/vczjk/i48;Llyiahf/vczjk/wa5;Landroid/content/Context;Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;Llyiahf/vczjk/cp8;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/m08;->OooOOO0:Ljava/lang/String;

    iput-object p2, p0, Llyiahf/vczjk/m08;->OooOOO:Ljava/lang/String;

    iput-object p3, p0, Llyiahf/vczjk/m08;->OooOOOO:Llyiahf/vczjk/hb8;

    iput-object p4, p0, Llyiahf/vczjk/m08;->OooOOOo:Llyiahf/vczjk/i48;

    iput-object p5, p0, Llyiahf/vczjk/m08;->OooOOo0:Llyiahf/vczjk/wa5;

    iput-object p6, p0, Llyiahf/vczjk/m08;->OooOOo:Landroid/content/Context;

    iput-object p7, p0, Llyiahf/vczjk/m08;->OooOOoo:Llyiahf/vczjk/qs5;

    iput-object p8, p0, Llyiahf/vczjk/m08;->OooOo00:Llyiahf/vczjk/qs5;

    iput-object p9, p0, Llyiahf/vczjk/m08;->OooOo0:Llyiahf/vczjk/cp8;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    check-cast p1, Llyiahf/vczjk/iq;

    const-string v0, "$this$AppBarRow"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/w77;

    iget-object v1, p0, Llyiahf/vczjk/m08;->OooOOOO:Llyiahf/vczjk/hb8;

    iget-object v2, p0, Llyiahf/vczjk/m08;->OooOOOo:Llyiahf/vczjk/i48;

    const/4 v3, 0x6

    invoke-direct {v0, v3, v1, v2}, Llyiahf/vczjk/w77;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/yb1;->OooO0o:Llyiahf/vczjk/a91;

    iget-object p1, p1, Llyiahf/vczjk/iq;->OooO00o:Llyiahf/vczjk/jq;

    const-string v2, "Search"

    invoke-virtual {p1, v0, v1, v2}, Llyiahf/vczjk/jq;->OooO00o(Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Ljava/lang/String;)V

    new-instance v3, Llyiahf/vczjk/f08;

    iget-object v4, p0, Llyiahf/vczjk/m08;->OooOOo0:Llyiahf/vczjk/wa5;

    iget-object v5, p0, Llyiahf/vczjk/m08;->OooOOo:Landroid/content/Context;

    iget-object v6, p0, Llyiahf/vczjk/m08;->OooOOoo:Llyiahf/vczjk/qs5;

    iget-object v7, p0, Llyiahf/vczjk/m08;->OooOo00:Llyiahf/vczjk/qs5;

    const/4 v8, 0x1

    invoke-direct/range {v3 .. v8}, Llyiahf/vczjk/f08;-><init>(Llyiahf/vczjk/wa5;Landroid/content/Context;Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;I)V

    sget-object v0, Llyiahf/vczjk/yb1;->OooO0oO:Llyiahf/vczjk/a91;

    const-string v1, "Add"

    invoke-virtual {p1, v3, v0, v1}, Llyiahf/vczjk/jq;->OooO00o(Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/w77;

    iget-object v1, p0, Llyiahf/vczjk/m08;->OooOo0:Llyiahf/vczjk/cp8;

    const/4 v2, 0x7

    invoke-direct {v0, v2, v1, v7}, Llyiahf/vczjk/w77;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/yb1;->OooO0oo:Llyiahf/vczjk/a91;

    iget-object v2, p0, Llyiahf/vczjk/m08;->OooOOO0:Ljava/lang/String;

    invoke-virtual {p1, v0, v1, v2}, Llyiahf/vczjk/jq;->OooO00o(Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/kt;

    const/16 v1, 0x9

    invoke-direct {v0, v5, v1}, Llyiahf/vczjk/kt;-><init>(Landroid/content/Context;I)V

    sget-object v1, Llyiahf/vczjk/yb1;->OooO:Llyiahf/vczjk/a91;

    iget-object v2, p0, Llyiahf/vczjk/m08;->OooOOO:Ljava/lang/String;

    invoke-virtual {p1, v0, v1, v2}, Llyiahf/vczjk/jq;->OooO00o(Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Ljava/lang/String;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
