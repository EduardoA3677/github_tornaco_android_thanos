.class public final Llyiahf/vczjk/ek3;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/fk3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fk3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ek3;->this$0:Llyiahf/vczjk/fk3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/yba;

    iget-object v0, p0, Llyiahf/vczjk/ek3;->this$0:Llyiahf/vczjk/fk3;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fk3;->OooO0oO(Llyiahf/vczjk/yba;)V

    iget-object v0, p0, Llyiahf/vczjk/ek3;->this$0:Llyiahf/vczjk/fk3;

    iget-object v0, v0, Llyiahf/vczjk/fk3;->OooO:Llyiahf/vczjk/rm4;

    if-eqz v0, :cond_0

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
