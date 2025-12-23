.class public final synthetic Llyiahf/vczjk/xla;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:F

.field public final synthetic OooOOO0:Ljava/util/List;

.field public final synthetic OooOOOO:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOOo:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOo:Llyiahf/vczjk/n62;

.field public final synthetic OooOOo0:Llyiahf/vczjk/dw4;


# direct methods
.method public synthetic constructor <init>(Ljava/util/List;FLlyiahf/vczjk/qs5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/dw4;Llyiahf/vczjk/n62;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/xla;->OooOOO0:Ljava/util/List;

    iput p2, p0, Llyiahf/vczjk/xla;->OooOOO:F

    iput-object p3, p0, Llyiahf/vczjk/xla;->OooOOOO:Llyiahf/vczjk/qs5;

    iput-object p4, p0, Llyiahf/vczjk/xla;->OooOOOo:Llyiahf/vczjk/oe3;

    iput-object p5, p0, Llyiahf/vczjk/xla;->OooOOo0:Llyiahf/vczjk/dw4;

    iput-object p6, p0, Llyiahf/vczjk/xla;->OooOOo:Llyiahf/vczjk/n62;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    check-cast p1, Llyiahf/vczjk/fv4;

    const-string v0, "$this$LazyColumn"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/bma;

    iget-object v2, p0, Llyiahf/vczjk/xla;->OooOOO0:Ljava/util/List;

    iget-object v6, p0, Llyiahf/vczjk/xla;->OooOOo0:Llyiahf/vczjk/dw4;

    iget-object v7, p0, Llyiahf/vczjk/xla;->OooOOo:Llyiahf/vczjk/n62;

    iget v3, p0, Llyiahf/vczjk/xla;->OooOOO:F

    iget-object v4, p0, Llyiahf/vczjk/xla;->OooOOOO:Llyiahf/vczjk/qs5;

    iget-object v5, p0, Llyiahf/vczjk/xla;->OooOOOo:Llyiahf/vczjk/oe3;

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/bma;-><init>(Ljava/util/List;FLlyiahf/vczjk/qs5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/dw4;Llyiahf/vczjk/n62;)V

    new-instance v0, Llyiahf/vczjk/a91;

    const v2, 0x690f6af2

    const/4 v3, 0x1

    invoke-direct {v0, v2, v1, v3}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    const v1, 0x7fffffff

    const/4 v2, 0x0

    const/4 v3, 0x6

    invoke-static {p1, v1, v2, v0, v3}, Llyiahf/vczjk/fv4;->OooO(Llyiahf/vczjk/fv4;ILlyiahf/vczjk/oe3;Llyiahf/vczjk/a91;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
