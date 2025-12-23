.class public final Llyiahf/vczjk/w25;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/k86;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/o000OOo0;

.field public OooO0O0:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/vy2;Llyiahf/vczjk/o000OOo0;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 p1, 0x0

    iput-boolean p1, p0, Llyiahf/vczjk/w25;->OooO0O0:Z

    iput-object p2, p0, Llyiahf/vczjk/w25;->OooO00o:Llyiahf/vczjk/o000OOo0;

    return-void
.end method


# virtual methods
.method public final onChanged(Ljava/lang/Object;)V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/w25;->OooO00o:Llyiahf/vczjk/o000OOo0;

    check-cast p1, Llyiahf/vczjk/qx8;

    const/4 v1, 0x0

    iput-boolean v1, v0, Llyiahf/vczjk/o000OOo0;->OooOoOO:Z

    iget-object v2, v0, Llyiahf/vczjk/o000OOo0;->OooOOO0:Ljava/util/HashSet;

    invoke-virtual {v2}, Ljava/util/HashSet;->clear()V

    iget-object v2, v0, Llyiahf/vczjk/o000OOo0;->OooOOO:Ljava/util/HashSet;

    invoke-virtual {v2}, Ljava/util/HashSet;->clear()V

    iget-object v2, v0, Llyiahf/vczjk/o000OOo0;->OooOo0O:Llyiahf/vczjk/ly2;

    iput-object p1, v2, Llyiahf/vczjk/ly2;->OooO0o:Ljava/lang/Object;

    invoke-virtual {v2}, Landroidx/recyclerview/widget/OooOO0O;->OooO0o()V

    iget-object p1, v0, Llyiahf/vczjk/o000OOo0;->OooOo0o:Landroid/widget/TextView;

    if-eqz p1, :cond_0

    iget-object v2, v0, Llyiahf/vczjk/o000OOo0;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Ljava/io/File;

    invoke-virtual {v2}, Ljava/io/File;->getPath()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p1, v2}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    :cond_0
    invoke-virtual {v0}, Landroidx/fragment/app/Oooo0;->getLoaderManager()Llyiahf/vczjk/u25;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/y25;

    iget-object p1, p1, Llyiahf/vczjk/y25;->OooO0O0:Llyiahf/vczjk/x25;

    iget-boolean v0, p1, Llyiahf/vczjk/x25;->OooO0OO:Z

    if-nez v0, :cond_3

    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object v0

    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    move-result-object v2

    if-ne v0, v2, :cond_2

    iget-object v0, p1, Llyiahf/vczjk/x25;->OooO0O0:Llyiahf/vczjk/ly8;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ly8;->OooO0OO(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/v25;

    const/4 v2, 0x1

    if-eqz v0, :cond_1

    invoke-virtual {v0, v2}, Llyiahf/vczjk/v25;->OooOO0O(Z)Llyiahf/vczjk/vy2;

    iget-object p1, p1, Llyiahf/vczjk/x25;->OooO0O0:Llyiahf/vczjk/ly8;

    iget-object v0, p1, Llyiahf/vczjk/ly8;->OooOOO:[I

    iget v3, p1, Llyiahf/vczjk/ly8;->OooOOOo:I

    invoke-static {v0, v3, v1}, Llyiahf/vczjk/rs;->OooO0oo([III)I

    move-result v0

    if-ltz v0, :cond_1

    iget-object v1, p1, Llyiahf/vczjk/ly8;->OooOOOO:[Ljava/lang/Object;

    aget-object v3, v1, v0

    sget-object v4, Llyiahf/vczjk/t51;->OooOO0:Ljava/lang/Object;

    if-eq v3, v4, :cond_1

    aput-object v4, v1, v0

    iput-boolean v2, p1, Llyiahf/vczjk/ly8;->OooOOO0:Z

    :cond_1
    iput-boolean v2, p0, Llyiahf/vczjk/w25;->OooO0O0:Z

    return-void

    :cond_2
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "destroyLoader must be called on the main thread"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_3
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "Called while creating a loader"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/w25;->OooO00o:Llyiahf/vczjk/o000OOo0;

    invoke-virtual {v0}, Landroidx/fragment/app/Oooo0;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
