.class public final Llyiahf/vczjk/l65;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $placeableResult:Llyiahf/vczjk/qw6;

.field final synthetic this$0:Llyiahf/vczjk/o65;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qw6;Llyiahf/vczjk/o65;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/l65;->$placeableResult:Llyiahf/vczjk/qw6;

    iput-object p2, p0, Llyiahf/vczjk/l65;->this$0:Llyiahf/vczjk/o65;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/l65;->$placeableResult:Llyiahf/vczjk/qw6;

    iget-object v0, v0, Llyiahf/vczjk/qw6;->OooOOO0:Llyiahf/vczjk/mf5;

    invoke-interface {v0}, Llyiahf/vczjk/mf5;->OooO0OO()Llyiahf/vczjk/oe3;

    move-result-object v0

    if-eqz v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/l65;->this$0:Llyiahf/vczjk/o65;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v2, Llyiahf/vczjk/n65;

    invoke-direct {v2, v1}, Llyiahf/vczjk/n65;-><init>(Llyiahf/vczjk/o65;)V

    invoke-interface {v0, v2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
