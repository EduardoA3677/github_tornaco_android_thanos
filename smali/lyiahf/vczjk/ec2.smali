.class public final Llyiahf/vczjk/ec2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bja;


# instance fields
.field public OooOOO:Z

.field public OooOOO0:Z

.field public OooOOOO:Z

.field public final OooOOOo:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/ec2;->OooOOO0:Z

    new-instance v0, Ljava/util/ArrayDeque;

    invoke-direct {v0}, Ljava/util/ArrayDeque;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/ec2;->OooOOOo:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(ZZZLlyiahf/vczjk/uz5;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Llyiahf/vczjk/ec2;->OooOOO0:Z

    iput-boolean p2, p0, Llyiahf/vczjk/ec2;->OooOOO:Z

    iput-boolean p3, p0, Llyiahf/vczjk/ec2;->OooOOOO:Z

    iput-object p4, p0, Llyiahf/vczjk/ec2;->OooOOOo:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public OooO00o()V
    .locals 4

    iget-boolean v0, p0, Llyiahf/vczjk/ec2;->OooOOOO:Z

    if-eqz v0, :cond_0

    return-void

    :cond_0
    const/4 v0, 0x0

    const/4 v1, 0x1

    :try_start_0
    iput-boolean v1, p0, Llyiahf/vczjk/ec2;->OooOOOO:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :cond_1
    :goto_0
    iget-object v2, p0, Llyiahf/vczjk/ec2;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Ljava/util/ArrayDeque;

    :try_start_1
    invoke-virtual {v2}, Ljava/util/ArrayDeque;->isEmpty()Z

    move-result v3

    if-nez v3, :cond_5

    iget-boolean v3, p0, Llyiahf/vczjk/ec2;->OooOOO:Z

    if-nez v3, :cond_3

    iget-boolean v3, p0, Llyiahf/vczjk/ec2;->OooOOO0:Z

    if-nez v3, :cond_2

    goto :goto_1

    :cond_2
    move v3, v0

    goto :goto_2

    :cond_3
    :goto_1
    move v3, v1

    :goto_2
    if-nez v3, :cond_4

    goto :goto_3

    :cond_4
    invoke-virtual {v2}, Ljava/util/ArrayDeque;->poll()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Runnable;

    if-eqz v2, :cond_1

    invoke-interface {v2}, Ljava/lang/Runnable;->run()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v1

    goto :goto_4

    :cond_5
    :goto_3
    iput-boolean v0, p0, Llyiahf/vczjk/ec2;->OooOOOO:Z

    return-void

    :goto_4
    iput-boolean v0, p0, Llyiahf/vczjk/ec2;->OooOOOO:Z

    throw v1
.end method

.method public OooOOOO(Landroid/view/View;Llyiahf/vczjk/ioa;Llyiahf/vczjk/cja;)Llyiahf/vczjk/ioa;
    .locals 4

    iget-boolean v0, p0, Llyiahf/vczjk/ec2;->OooOOO0:Z

    if-eqz v0, :cond_0

    iget v0, p3, Llyiahf/vczjk/cja;->OooO0Oo:I

    invoke-virtual {p2}, Llyiahf/vczjk/ioa;->OooO00o()I

    move-result v1

    add-int/2addr v1, v0

    iput v1, p3, Llyiahf/vczjk/cja;->OooO0Oo:I

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/ls6;->OooOO0o(Landroid/view/View;)Z

    move-result v0

    iget-boolean v1, p0, Llyiahf/vczjk/ec2;->OooOOO:Z

    if-eqz v1, :cond_2

    if-eqz v0, :cond_1

    iget v1, p3, Llyiahf/vczjk/cja;->OooO0OO:I

    invoke-virtual {p2}, Llyiahf/vczjk/ioa;->OooO0O0()I

    move-result v2

    add-int/2addr v2, v1

    iput v2, p3, Llyiahf/vczjk/cja;->OooO0OO:I

    goto :goto_0

    :cond_1
    iget v1, p3, Llyiahf/vczjk/cja;->OooO00o:I

    invoke-virtual {p2}, Llyiahf/vczjk/ioa;->OooO0O0()I

    move-result v2

    add-int/2addr v2, v1

    iput v2, p3, Llyiahf/vczjk/cja;->OooO00o:I

    :cond_2
    :goto_0
    iget-boolean v1, p0, Llyiahf/vczjk/ec2;->OooOOOO:Z

    if-eqz v1, :cond_4

    if-eqz v0, :cond_3

    iget v0, p3, Llyiahf/vczjk/cja;->OooO00o:I

    invoke-virtual {p2}, Llyiahf/vczjk/ioa;->OooO0OO()I

    move-result v1

    add-int/2addr v1, v0

    iput v1, p3, Llyiahf/vczjk/cja;->OooO00o:I

    goto :goto_1

    :cond_3
    iget v0, p3, Llyiahf/vczjk/cja;->OooO0OO:I

    invoke-virtual {p2}, Llyiahf/vczjk/ioa;->OooO0OO()I

    move-result v1

    add-int/2addr v1, v0

    iput v1, p3, Llyiahf/vczjk/cja;->OooO0OO:I

    :cond_4
    :goto_1
    iget v0, p3, Llyiahf/vczjk/cja;->OooO00o:I

    iget v1, p3, Llyiahf/vczjk/cja;->OooO0O0:I

    iget v2, p3, Llyiahf/vczjk/cja;->OooO0OO:I

    iget v3, p3, Llyiahf/vczjk/cja;->OooO0Oo:I

    invoke-virtual {p1, v0, v1, v2, v3}, Landroid/view/View;->setPaddingRelative(IIII)V

    iget-object v0, p0, Llyiahf/vczjk/ec2;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/uz5;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/uz5;->OooOOOO(Landroid/view/View;Llyiahf/vczjk/ioa;Llyiahf/vczjk/cja;)Llyiahf/vczjk/ioa;

    return-object p2
.end method
