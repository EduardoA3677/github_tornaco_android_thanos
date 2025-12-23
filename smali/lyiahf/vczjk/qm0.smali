.class public final Llyiahf/vczjk/qm0;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $this_apply:Llyiahf/vczjk/tm0;

.field final synthetic this$0:Llyiahf/vczjk/rm0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/rm0;Llyiahf/vczjk/tm0;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qm0;->this$0:Llyiahf/vczjk/rm0;

    iput-object p2, p0, Llyiahf/vczjk/qm0;->$this_apply:Llyiahf/vczjk/tm0;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/qm0;->this$0:Llyiahf/vczjk/rm0;

    iget-object v0, v0, Llyiahf/vczjk/rm0;->OooOoo:Llyiahf/vczjk/oe3;

    iget-object v1, p0, Llyiahf/vczjk/qm0;->$this_apply:Llyiahf/vczjk/tm0;

    invoke-interface {v0, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
