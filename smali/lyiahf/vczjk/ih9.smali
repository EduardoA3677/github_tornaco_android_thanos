.class public final Llyiahf/vczjk/ih9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/lh9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lh9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ih9;->this$0:Llyiahf/vczjk/lh9;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/ih9;->this$0:Llyiahf/vczjk/lh9;

    iget-object v1, v0, Llyiahf/vczjk/lh9;->Oooo:Llyiahf/vczjk/fh9;

    if-nez v1, :cond_0

    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    return-object p1

    :cond_0
    iget-object v0, v0, Llyiahf/vczjk/lh9;->Oooo0o0:Llyiahf/vczjk/oe3;

    if-eqz v0, :cond_1

    invoke-interface {v0, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/ih9;->this$0:Llyiahf/vczjk/lh9;

    iget-object v1, v0, Llyiahf/vczjk/lh9;->Oooo:Llyiahf/vczjk/fh9;

    if-nez v1, :cond_2

    goto :goto_0

    :cond_2
    iput-boolean p1, v1, Llyiahf/vczjk/fh9;->OooO0OO:Z

    :goto_0
    invoke-static {v0}, Llyiahf/vczjk/ll6;->OooO(Llyiahf/vczjk/ne8;)V

    invoke-static {v0}, Llyiahf/vczjk/t51;->Oooo00o(Llyiahf/vczjk/go4;)V

    invoke-static {v0}, Llyiahf/vczjk/ye5;->OooOoO0(Llyiahf/vczjk/fg2;)V

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1
.end method
