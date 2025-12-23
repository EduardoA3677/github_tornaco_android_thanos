.class public final Llyiahf/vczjk/nu5;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/ie;


# direct methods
.method public constructor <init>(Landroid/os/Bundle;)V
    .locals 6

    const-string v0, "state"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const-class v0, Llyiahf/vczjk/nu5;

    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v0

    invoke-virtual {p1, v0}, Landroid/os/Bundle;->setClassLoader(Ljava/lang/ClassLoader;)V

    new-instance v0, Llyiahf/vczjk/ie;

    const-string v1, "state"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    const-string v1, "nav-entry-state:id"

    invoke-virtual {p1, v1}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    const/4 v3, 0x0

    if-eqz v2, :cond_2

    iput-object v2, v0, Llyiahf/vczjk/ie;->OooO0O0:Ljava/lang/Object;

    const-string v1, "nav-entry-state:destination-id"

    const/high16 v2, -0x80000000

    invoke-virtual {p1, v1, v2}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    move-result v4

    if-ne v4, v2, :cond_1

    const v2, 0x7fffffff

    invoke-virtual {p1, v1, v2}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    move-result v5

    if-eq v5, v2, :cond_0

    goto :goto_0

    :cond_0
    invoke-static {v1}, Llyiahf/vczjk/tp6;->OooOooO(Ljava/lang/String;)V

    throw v3

    :cond_1
    :goto_0
    iput v4, v0, Llyiahf/vczjk/ie;->OooO00o:I

    const-string v1, "nav-entry-state:args"

    invoke-static {p1, v1}, Llyiahf/vczjk/vo6;->OooO0oO(Landroid/os/Bundle;Ljava/lang/String;)Landroid/os/Bundle;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/ie;->OooO0OO:Ljava/lang/Object;

    const-string v1, "nav-entry-state:saved-state"

    invoke-static {p1, v1}, Llyiahf/vczjk/vo6;->OooO0oO(Landroid/os/Bundle;Ljava/lang/String;)Landroid/os/Bundle;

    move-result-object p1

    iput-object p1, v0, Llyiahf/vczjk/ie;->OooO0Oo:Ljava/lang/Object;

    iput-object v0, p0, Llyiahf/vczjk/nu5;->OooO00o:Llyiahf/vczjk/ie;

    return-void

    :cond_2
    invoke-static {v1}, Llyiahf/vczjk/tp6;->OooOooO(Ljava/lang/String;)V

    throw v3
.end method

.method public constructor <init>(Llyiahf/vczjk/ku5;)V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/ie;

    iget-object v1, p1, Llyiahf/vczjk/ku5;->OooOOO:Llyiahf/vczjk/av5;

    iget-object v1, v1, Llyiahf/vczjk/av5;->OooOOO:Llyiahf/vczjk/j1;

    iget v1, v1, Llyiahf/vczjk/j1;->OooO00o:I

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iget-object v2, p1, Llyiahf/vczjk/ku5;->OooOOo:Ljava/lang/String;

    iput-object v2, v0, Llyiahf/vczjk/ie;->OooO0O0:Ljava/lang/Object;

    iput v1, v0, Llyiahf/vczjk/ie;->OooO00o:I

    iget-object p1, p1, Llyiahf/vczjk/ku5;->OooOo00:Llyiahf/vczjk/mu5;

    invoke-virtual {p1}, Llyiahf/vczjk/mu5;->OooO00o()Landroid/os/Bundle;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/ie;->OooO0OO:Ljava/lang/Object;

    const/4 v1, 0x0

    new-array v2, v1, [Llyiahf/vczjk/xn6;

    invoke-static {v2, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v1

    check-cast v1, [Llyiahf/vczjk/xn6;

    invoke-static {v1}, Llyiahf/vczjk/qqa;->OooOOOo([Llyiahf/vczjk/xn6;)Landroid/os/Bundle;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/ie;->OooO0Oo:Ljava/lang/Object;

    iget-object p1, p1, Llyiahf/vczjk/mu5;->OooO0oo:Llyiahf/vczjk/f68;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/f68;->OooO0O0(Landroid/os/Bundle;)V

    iput-object v0, p0, Llyiahf/vczjk/nu5;->OooO00o:Llyiahf/vczjk/ie;

    return-void
.end method
