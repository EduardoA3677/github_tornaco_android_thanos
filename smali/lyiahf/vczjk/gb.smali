.class public final Llyiahf/vczjk/gb;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/hb;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hb;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/gb;->this$0:Llyiahf/vczjk/hb;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/u98;

    iget-object v0, p0, Llyiahf/vczjk/gb;->this$0:Llyiahf/vczjk/hb;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v1, p1, Llyiahf/vczjk/u98;->OooOOO:Ljava/util/ArrayList;

    invoke-virtual {v1, p1}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_0

    goto :goto_0

    :cond_0
    iget-object v1, v0, Llyiahf/vczjk/hb;->OooO0Oo:Llyiahf/vczjk/xa;

    invoke-virtual {v1}, Llyiahf/vczjk/xa;->getSnapshotObserver()Llyiahf/vczjk/vg6;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/fb;

    invoke-direct {v2, p1, v0}, Llyiahf/vczjk/fb;-><init>(Llyiahf/vczjk/u98;Llyiahf/vczjk/hb;)V

    iget-object v0, v0, Llyiahf/vczjk/hb;->Oooo0oo:Llyiahf/vczjk/gb;

    invoke-virtual {v1, p1, v0, v2}, Llyiahf/vczjk/vg6;->OooO00o(Llyiahf/vczjk/ug6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;)V

    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
