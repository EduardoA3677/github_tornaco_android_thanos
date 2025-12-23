.class public final Llyiahf/vczjk/dr1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/hr1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hr1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/dr1;->this$0:Llyiahf/vczjk/hr1;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/dr1;->this$0:Llyiahf/vczjk/hr1;

    iget-object v1, v0, Llyiahf/vczjk/hr1;->OooOooo:Llyiahf/vczjk/lx4;

    iget-object v2, v0, Llyiahf/vczjk/hr1;->Oooo0OO:Llyiahf/vczjk/w83;

    iget-boolean v0, v0, Llyiahf/vczjk/hr1;->Oooo000:Z

    invoke-virtual {v1}, Llyiahf/vczjk/lx4;->OooO0O0()Z

    move-result v3

    if-nez v3, :cond_0

    invoke-static {v2}, Llyiahf/vczjk/w83;->OooO0O0(Llyiahf/vczjk/w83;)V

    goto :goto_0

    :cond_0
    if-nez v0, :cond_1

    iget-object v0, v1, Llyiahf/vczjk/lx4;->OooO0OO:Llyiahf/vczjk/dx8;

    if-eqz v0, :cond_1

    check-cast v0, Llyiahf/vczjk/q52;

    invoke-virtual {v0}, Llyiahf/vczjk/q52;->OooO0O0()V

    :cond_1
    :goto_0
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object v0
.end method
