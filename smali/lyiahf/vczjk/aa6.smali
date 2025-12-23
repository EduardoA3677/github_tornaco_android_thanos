.class public final Llyiahf/vczjk/aa6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/ha6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ha6;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/aa6;->this$0:Llyiahf/vczjk/ha6;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/n40;

    const-string v0, "backEvent"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/aa6;->this$0:Llyiahf/vczjk/ha6;

    iget-object v1, v0, Llyiahf/vczjk/ha6;->OooO0OO:Llyiahf/vczjk/y96;

    if-nez v1, :cond_2

    iget-object v0, v0, Llyiahf/vczjk/ha6;->OooO0O0:Llyiahf/vczjk/xx;

    invoke-virtual {v0}, Llyiahf/vczjk/xx;->OooO00o()I

    move-result v1

    invoke-virtual {v0, v1}, Ljava/util/AbstractList;->listIterator(I)Ljava/util/ListIterator;

    move-result-object v0

    :cond_0
    invoke-interface {v0}, Ljava/util/ListIterator;->hasPrevious()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {v0}, Ljava/util/ListIterator;->previous()Ljava/lang/Object;

    move-result-object v1

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/y96;

    iget-boolean v2, v2, Llyiahf/vczjk/y96;->OooO00o:Z

    if-eqz v2, :cond_0

    goto :goto_0

    :cond_1
    const/4 v1, 0x0

    :goto_0
    check-cast v1, Llyiahf/vczjk/y96;

    :cond_2
    if-eqz v1, :cond_3

    invoke-virtual {v1, p1}, Llyiahf/vczjk/y96;->OooO0OO(Llyiahf/vczjk/n40;)V

    :cond_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
