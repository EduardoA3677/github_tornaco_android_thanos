.class public final Llyiahf/vczjk/e57$OooO00o;
.super Llyiahf/vczjk/pm2;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Llyiahf/vczjk/e57;->onActivityPreCreated(Landroid/app/Activity;Landroid/os/Bundle;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/f57;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/f57;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/e57$OooO00o;->this$0:Llyiahf/vczjk/f57;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onActivityPostResumed(Landroid/app/Activity;)V
    .locals 1

    const-string v0, "activity"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/e57$OooO00o;->this$0:Llyiahf/vczjk/f57;

    invoke-virtual {p1}, Llyiahf/vczjk/f57;->OooO0O0()V

    return-void
.end method

.method public onActivityPostStarted(Landroid/app/Activity;)V
    .locals 2

    const-string v0, "activity"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/e57$OooO00o;->this$0:Llyiahf/vczjk/f57;

    iget v0, p1, Llyiahf/vczjk/f57;->OooOOO0:I

    const/4 v1, 0x1

    add-int/2addr v0, v1

    iput v0, p1, Llyiahf/vczjk/f57;->OooOOO0:I

    if-ne v0, v1, :cond_0

    iget-boolean v0, p1, Llyiahf/vczjk/f57;->OooOOOo:Z

    if-eqz v0, :cond_0

    iget-object v0, p1, Llyiahf/vczjk/f57;->OooOOo:Llyiahf/vczjk/wy4;

    sget-object v1, Llyiahf/vczjk/iy4;->ON_START:Llyiahf/vczjk/iy4;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/wy4;->OooO0o(Llyiahf/vczjk/iy4;)V

    const/4 v0, 0x0

    iput-boolean v0, p1, Llyiahf/vczjk/f57;->OooOOOo:Z

    :cond_0
    return-void
.end method
