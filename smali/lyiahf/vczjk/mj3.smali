.class public final Llyiahf/vczjk/mj3;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/nj3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nj3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/mj3;->this$0:Llyiahf/vczjk/nj3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/hg2;

    iget-object v0, p0, Llyiahf/vczjk/mj3;->this$0:Llyiahf/vczjk/nj3;

    invoke-interface {p1}, Llyiahf/vczjk/hg2;->Ooooo0o()Llyiahf/vczjk/uqa;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/nj3;->OooOOOo:Llyiahf/vczjk/ze3;

    if-eqz v0, :cond_0

    invoke-interface {p1}, Llyiahf/vczjk/hg2;->Ooooo0o()Llyiahf/vczjk/uqa;

    move-result-object p1

    iget-object p1, p1, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/kj3;

    invoke-interface {v0, v1, p1}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
