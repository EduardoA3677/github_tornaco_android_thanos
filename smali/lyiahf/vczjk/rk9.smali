.class public final Llyiahf/vczjk/rk9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $state:Llyiahf/vczjk/eo1;

.field final synthetic $this_contextMenuBuilder$inlined:Llyiahf/vczjk/mk9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/eo1;Llyiahf/vczjk/mk9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/rk9;->$state:Llyiahf/vczjk/eo1;

    iput-object p2, p0, Llyiahf/vczjk/rk9;->$this_contextMenuBuilder$inlined:Llyiahf/vczjk/mk9;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/rk9;->$this_contextMenuBuilder$inlined:Llyiahf/vczjk/mk9;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Llyiahf/vczjk/mk9;->OooO0Oo(Z)Llyiahf/vczjk/r09;

    iget-object v0, p0, Llyiahf/vczjk/rk9;->$state:Llyiahf/vczjk/eo1;

    invoke-static {v0}, Llyiahf/vczjk/nqa;->OooOOOO(Llyiahf/vczjk/eo1;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
