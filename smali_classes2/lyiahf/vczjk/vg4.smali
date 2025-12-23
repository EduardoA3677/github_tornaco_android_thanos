.class public final Llyiahf/vczjk/vg4;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/yg4;

.field public final synthetic OooOOO0:I

.field public final OooOOOO:Llyiahf/vczjk/wg4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wg4;Llyiahf/vczjk/yg4;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/vg4;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/vg4;->OooOOOO:Llyiahf/vczjk/wg4;

    iput-object p2, p0, Llyiahf/vczjk/vg4;->OooOOO:Llyiahf/vczjk/yg4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/yg4;Llyiahf/vczjk/wg4;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/vg4;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/vg4;->OooOOO:Llyiahf/vczjk/yg4;

    iput-object p2, p0, Llyiahf/vczjk/vg4;->OooOOOO:Llyiahf/vczjk/wg4;

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget v0, p0, Llyiahf/vczjk/vg4;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/vg4;->OooOOOO:Llyiahf/vczjk/wg4;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/wg4;->OooO0oO:[Llyiahf/vczjk/th4;

    const/4 v2, 0x1

    aget-object v1, v1, v2

    iget-object v0, v0, Llyiahf/vczjk/wg4;->OooO0Oo:Llyiahf/vczjk/wm7;

    invoke-virtual {v0}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    const-string v1, "getValue(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/jg5;

    sget-object v1, Llyiahf/vczjk/wf4;->OooOOO0:Llyiahf/vczjk/wf4;

    iget-object v2, p0, Llyiahf/vczjk/vg4;->OooOOO:Llyiahf/vczjk/yg4;

    invoke-virtual {v2, v0, v1}, Llyiahf/vczjk/yf4;->OooOO0o(Llyiahf/vczjk/jg5;Llyiahf/vczjk/wf4;)Ljava/util/List;

    move-result-object v0

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/vg4;->OooOOOO:Llyiahf/vczjk/wg4;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/wg4;->OooO0oO:[Llyiahf/vczjk/th4;

    const/4 v2, 0x0

    aget-object v1, v1, v2

    iget-object v0, v0, Llyiahf/vczjk/wg4;->OooO0OO:Llyiahf/vczjk/wm7;

    invoke-virtual {v0}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/tm7;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/tm7;->OooO0O0:Llyiahf/vczjk/fq3;

    sget-object v2, Llyiahf/vczjk/ik4;->OooOo00:Llyiahf/vczjk/ik4;

    iget-object v3, v0, Llyiahf/vczjk/fq3;->OooO0OO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/ik4;

    if-ne v3, v2, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/fq3;->OooO0oo:Ljava/lang/Object;

    check-cast v0, Ljava/lang/String;

    goto :goto_0

    :cond_0
    move-object v0, v1

    :goto_0
    if-eqz v0, :cond_1

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v2

    if-lez v2, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/vg4;->OooOOO:Llyiahf/vczjk/yg4;

    iget-object v1, v1, Llyiahf/vczjk/yg4;->OooOOO:Ljava/lang/Class;

    invoke-virtual {v1}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v1

    const/16 v2, 0x2f

    const/16 v3, 0x2e

    invoke-static {v0, v2, v3}, Llyiahf/vczjk/g79;->OooOooo(Ljava/lang/String;CC)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v1, v0}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v1

    :cond_1
    return-object v1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
