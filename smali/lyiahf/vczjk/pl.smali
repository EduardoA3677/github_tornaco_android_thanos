.class public final Llyiahf/vczjk/pl;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/vl;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/vl;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/pl;->this$0:Llyiahf/vczjk/vl;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/bz9;

    iget-object v0, p0, Llyiahf/vczjk/pl;->this$0:Llyiahf/vczjk/vl;

    iget-object v0, v0, Llyiahf/vczjk/vl;->OooO00o:Llyiahf/vczjk/ga;

    invoke-virtual {v0}, Llyiahf/vczjk/ga;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/e47;

    iget-object v1, p0, Llyiahf/vczjk/pl;->this$0:Llyiahf/vczjk/vl;

    iget-object v1, v1, Llyiahf/vczjk/vl;->OooO0O0:Llyiahf/vczjk/da;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v2, p1, Llyiahf/vczjk/bz9;->OooO00o:Llyiahf/vczjk/tz9;

    invoke-virtual {v2}, Llyiahf/vczjk/tz9;->OooO00o()Ljava/lang/Object;

    move-result-object v2

    instance-of v2, v2, Ljava/lang/Boolean;

    if-nez v2, :cond_0

    goto :goto_0

    :cond_0
    new-instance v2, Llyiahf/vczjk/z37;

    invoke-direct {v2, p1, v1, v0}, Llyiahf/vczjk/z37;-><init>(Llyiahf/vczjk/bz9;Llyiahf/vczjk/da;Llyiahf/vczjk/e47;)V

    invoke-virtual {v0, p1, v2}, Llyiahf/vczjk/e47;->OooO0O0(Ljava/lang/Object;Llyiahf/vczjk/oe3;)V

    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
