.class public final Llyiahf/vczjk/z96;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/ha6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ha6;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/z96;->this$0:Llyiahf/vczjk/ha6;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/n40;

    const-string v0, "backEvent"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/z96;->this$0:Llyiahf/vczjk/ha6;

    iget-object v1, v0, Llyiahf/vczjk/ha6;->OooO0O0:Llyiahf/vczjk/xx;

    invoke-virtual {v1}, Llyiahf/vczjk/xx;->OooO00o()I

    move-result v2

    invoke-virtual {v1, v2}, Ljava/util/AbstractList;->listIterator(I)Ljava/util/ListIterator;

    move-result-object v1

    :cond_0
    invoke-interface {v1}, Ljava/util/ListIterator;->hasPrevious()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {v1}, Ljava/util/ListIterator;->previous()Ljava/lang/Object;

    move-result-object v2

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/y96;

    iget-boolean v3, v3, Llyiahf/vczjk/y96;->OooO00o:Z

    if-eqz v3, :cond_0

    goto :goto_0

    :cond_1
    const/4 v2, 0x0

    :goto_0
    check-cast v2, Llyiahf/vczjk/y96;

    iget-object v1, v0, Llyiahf/vczjk/ha6;->OooO0OO:Llyiahf/vczjk/y96;

    if-eqz v1, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/ha6;->OooO0O0()V

    :cond_2
    iput-object v2, v0, Llyiahf/vczjk/ha6;->OooO0OO:Llyiahf/vczjk/y96;

    if-eqz v2, :cond_3

    invoke-virtual {v2, p1}, Llyiahf/vczjk/y96;->OooO0Oo(Llyiahf/vczjk/n40;)V

    :cond_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
