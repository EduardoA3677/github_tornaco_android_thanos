.class public final Llyiahf/vczjk/a68;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/d68;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/e68;

.field public OooO0O0:Z

.field public OooO0OO:Landroid/os/Bundle;

.field public final OooO0Oo:Llyiahf/vczjk/sc9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/e68;Llyiahf/vczjk/lha;)V
    .locals 1

    const-string v0, "savedStateRegistry"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "viewModelStoreOwner"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/a68;->OooO00o:Llyiahf/vczjk/e68;

    new-instance p1, Llyiahf/vczjk/ku7;

    const/4 v0, 0x3

    invoke-direct {p1, p2, v0}, Llyiahf/vczjk/ku7;-><init>(Ljava/lang/Object;I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/a68;->OooO0Oo:Llyiahf/vczjk/sc9;

    return-void
.end method


# virtual methods
.method public final OooO00o()Landroid/os/Bundle;
    .locals 6

    const/4 v0, 0x0

    new-array v1, v0, [Llyiahf/vczjk/xn6;

    invoke-static {v1, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v1

    check-cast v1, [Llyiahf/vczjk/xn6;

    invoke-static {v1}, Llyiahf/vczjk/qqa;->OooOOOo([Llyiahf/vczjk/xn6;)Landroid/os/Bundle;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/a68;->OooO0OO:Landroid/os/Bundle;

    if-eqz v2, :cond_0

    invoke-virtual {v1, v2}, Landroid/os/Bundle;->putAll(Landroid/os/Bundle;)V

    :cond_0
    iget-object v2, p0, Llyiahf/vczjk/a68;->OooO0Oo:Llyiahf/vczjk/sc9;

    invoke-virtual {v2}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/b68;

    iget-object v2, v2, Llyiahf/vczjk/b68;->OooO0O0:Ljava/util/LinkedHashMap;

    invoke-virtual {v2}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    move-result-object v2

    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_1
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_2

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/Map$Entry;

    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/x58;

    iget-object v3, v3, Llyiahf/vczjk/x58;->OooO0O0:Llyiahf/vczjk/mi;

    iget-object v3, v3, Llyiahf/vczjk/mi;->OooOOo0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/n61;

    invoke-virtual {v3}, Llyiahf/vczjk/n61;->OooO00o()Landroid/os/Bundle;

    move-result-object v3

    invoke-virtual {v3}, Landroid/os/BaseBundle;->isEmpty()Z

    move-result v5

    if-nez v5, :cond_1

    invoke-static {v1, v4, v3}, Llyiahf/vczjk/br6;->OooOoo0(Landroid/os/Bundle;Ljava/lang/String;Landroid/os/Bundle;)V

    goto :goto_0

    :cond_2
    iput-boolean v0, p0, Llyiahf/vczjk/a68;->OooO0O0:Z

    return-object v1
.end method

.method public final OooO0O0()V
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/a68;->OooO0O0:Z

    if-nez v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/a68;->OooO00o:Llyiahf/vczjk/e68;

    const-string v1, "androidx.lifecycle.internal.SavedStateHandlesProvider"

    invoke-virtual {v0, v1}, Llyiahf/vczjk/e68;->OooO00o(Ljava/lang/String;)Landroid/os/Bundle;

    move-result-object v0

    const/4 v1, 0x0

    new-array v2, v1, [Llyiahf/vczjk/xn6;

    invoke-static {v2, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v1

    check-cast v1, [Llyiahf/vczjk/xn6;

    invoke-static {v1}, Llyiahf/vczjk/qqa;->OooOOOo([Llyiahf/vczjk/xn6;)Landroid/os/Bundle;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/a68;->OooO0OO:Landroid/os/Bundle;

    if-eqz v2, :cond_0

    invoke-virtual {v1, v2}, Landroid/os/Bundle;->putAll(Landroid/os/Bundle;)V

    :cond_0
    if-eqz v0, :cond_1

    invoke-virtual {v1, v0}, Landroid/os/Bundle;->putAll(Landroid/os/Bundle;)V

    :cond_1
    iput-object v1, p0, Llyiahf/vczjk/a68;->OooO0OO:Landroid/os/Bundle;

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/a68;->OooO0O0:Z

    iget-object v0, p0, Llyiahf/vczjk/a68;->OooO0Oo:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/b68;

    :cond_2
    return-void
.end method
