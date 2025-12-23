.class public final Llyiahf/vczjk/uk9;
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

    iput-object p1, p0, Llyiahf/vczjk/uk9;->$state:Llyiahf/vczjk/eo1;

    iput-object p2, p0, Llyiahf/vczjk/uk9;->$this_contextMenuBuilder$inlined:Llyiahf/vczjk/mk9;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/uk9;->$this_contextMenuBuilder$inlined:Llyiahf/vczjk/mk9;

    iget-object v0, v0, Llyiahf/vczjk/mk9;->OooO0oO:Llyiahf/vczjk/rm4;

    if-eqz v0, :cond_0

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/uk9;->$state:Llyiahf/vczjk/eo1;

    invoke-static {v0}, Llyiahf/vczjk/nqa;->OooOOOO(Llyiahf/vczjk/eo1;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
