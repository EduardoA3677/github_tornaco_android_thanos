.class public final Llyiahf/vczjk/t76;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/j86;
.implements Llyiahf/vczjk/nc2;


# instance fields
.field public OooOOO:Llyiahf/vczjk/nc2;

.field public final synthetic OooOOO0:I

.field public OooOOOO:Z

.field public final OooOOOo:Ljava/lang/Object;

.field public OooOOo0:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/j86;Llyiahf/vczjk/nl1;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/t76;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/t76;->OooOOOo:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/t76;->OooOOo0:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/tp8;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/t76;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/t76;->OooOOOo:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/t76;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/t76;->OooOOO:Llyiahf/vczjk/nc2;

    invoke-interface {v0}, Llyiahf/vczjk/nc2;->OooO00o()V

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/t76;->OooOOO:Llyiahf/vczjk/nc2;

    invoke-interface {v0}, Llyiahf/vczjk/nc2;->OooO00o()V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0O0(Llyiahf/vczjk/nc2;)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/t76;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/t76;->OooOOO:Llyiahf/vczjk/nc2;

    invoke-static {v0, p1}, Llyiahf/vczjk/tc2;->OooO0o0(Llyiahf/vczjk/nc2;Llyiahf/vczjk/nc2;)Z

    move-result v0

    if-eqz v0, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/t76;->OooOOO:Llyiahf/vczjk/nc2;

    iget-object p1, p0, Llyiahf/vczjk/t76;->OooOOOo:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/tp8;

    invoke-interface {p1, p0}, Llyiahf/vczjk/tp8;->OooO0O0(Llyiahf/vczjk/nc2;)V

    :cond_0
    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/t76;->OooOOO:Llyiahf/vczjk/nc2;

    invoke-static {v0, p1}, Llyiahf/vczjk/tc2;->OooO0o0(Llyiahf/vczjk/nc2;Llyiahf/vczjk/nc2;)Z

    move-result v0

    if-eqz v0, :cond_1

    iput-object p1, p0, Llyiahf/vczjk/t76;->OooOOO:Llyiahf/vczjk/nc2;

    iget-object p1, p0, Llyiahf/vczjk/t76;->OooOOOo:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/j86;

    invoke-interface {p1, p0}, Llyiahf/vczjk/j86;->OooO0O0(Llyiahf/vczjk/nc2;)V

    :cond_1
    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0OO(Ljava/lang/Throwable;)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/t76;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-boolean v0, p0, Llyiahf/vczjk/t76;->OooOOOO:Z

    if-eqz v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/qu6;->OooOOOo(Ljava/lang/Throwable;)V

    goto :goto_0

    :cond_0
    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/t76;->OooOOOO:Z

    iget-object v0, p0, Llyiahf/vczjk/t76;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/tp8;

    invoke-interface {v0, p1}, Llyiahf/vczjk/tp8;->OooO0OO(Ljava/lang/Throwable;)V

    :goto_0
    return-void

    :pswitch_0
    iget-boolean v0, p0, Llyiahf/vczjk/t76;->OooOOOO:Z

    if-eqz v0, :cond_1

    invoke-static {p1}, Llyiahf/vczjk/qu6;->OooOOOo(Ljava/lang/Throwable;)V

    goto :goto_1

    :cond_1
    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/t76;->OooOOOO:Z

    iget-object v0, p0, Llyiahf/vczjk/t76;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/j86;

    invoke-interface {v0, p1}, Llyiahf/vczjk/j86;->OooO0OO(Ljava/lang/Throwable;)V

    :goto_1
    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0Oo()V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/t76;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-boolean v0, p0, Llyiahf/vczjk/t76;->OooOOOO:Z

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/t76;->OooOOOO:Z

    iget-object v0, p0, Llyiahf/vczjk/t76;->OooOOo0:Ljava/lang/Object;

    const/4 v1, 0x0

    iput-object v1, p0, Llyiahf/vczjk/t76;->OooOOo0:Ljava/lang/Object;

    if-nez v0, :cond_1

    move-object v0, v1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/t76;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/tp8;

    if-eqz v0, :cond_2

    invoke-interface {v1, v0}, Llyiahf/vczjk/tp8;->OooO0o0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    new-instance v0, Ljava/util/NoSuchElementException;

    invoke-direct {v0}, Ljava/util/NoSuchElementException;-><init>()V

    invoke-interface {v1, v0}, Llyiahf/vczjk/tp8;->OooO0OO(Ljava/lang/Throwable;)V

    :goto_0
    return-void

    :pswitch_0
    iget-boolean v0, p0, Llyiahf/vczjk/t76;->OooOOOO:Z

    if-eqz v0, :cond_3

    goto :goto_1

    :cond_3
    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/t76;->OooOOOO:Z

    iget-object v0, p0, Llyiahf/vczjk/t76;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/j86;

    invoke-interface {v0}, Llyiahf/vczjk/j86;->OooO0Oo()V

    :goto_1
    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooOO0O(Ljava/lang/Object;)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/t76;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-boolean v0, p0, Llyiahf/vczjk/t76;->OooOOOO:Z

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/t76;->OooOOo0:Ljava/lang/Object;

    if-eqz v0, :cond_1

    const/4 p1, 0x1

    iput-boolean p1, p0, Llyiahf/vczjk/t76;->OooOOOO:Z

    iget-object p1, p0, Llyiahf/vczjk/t76;->OooOOO:Llyiahf/vczjk/nc2;

    invoke-interface {p1}, Llyiahf/vczjk/nc2;->OooO00o()V

    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Sequence contains more than one element!"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/t76;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/tp8;

    invoke-interface {v0, p1}, Llyiahf/vczjk/tp8;->OooO0OO(Ljava/lang/Throwable;)V

    goto :goto_0

    :cond_1
    iput-object p1, p0, Llyiahf/vczjk/t76;->OooOOo0:Ljava/lang/Object;

    :goto_0
    return-void

    :pswitch_0
    iget-boolean v0, p0, Llyiahf/vczjk/t76;->OooOOOO:Z

    if-eqz v0, :cond_2

    goto :goto_1

    :cond_2
    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/t76;->OooOOo0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/nl1;

    invoke-interface {v0, p1}, Llyiahf/vczjk/nl1;->accept(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    iget-object v0, p0, Llyiahf/vczjk/t76;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/j86;

    invoke-interface {v0, p1}, Llyiahf/vczjk/j86;->OooOO0O(Ljava/lang/Object;)V

    goto :goto_1

    :catchall_0
    move-exception p1

    invoke-static {p1}, Llyiahf/vczjk/vc6;->Oooo(Ljava/lang/Throwable;)V

    iget-object v0, p0, Llyiahf/vczjk/t76;->OooOOO:Llyiahf/vczjk/nc2;

    invoke-interface {v0}, Llyiahf/vczjk/nc2;->OooO00o()V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/t76;->OooO0OO(Ljava/lang/Throwable;)V

    :goto_1
    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
