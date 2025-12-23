.class public final Llyiahf/vczjk/f22;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/o23;


# instance fields
.field public OooO00o:Llyiahf/vczjk/t02;

.field public final OooO0O0:Llyiahf/vczjk/vb2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/t02;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/f22;->OooO00o:Llyiahf/vczjk/t02;

    sget-object p1, Landroidx/compose/foundation/gestures/OooO0O0;->OooO0O0:Llyiahf/vczjk/vb2;

    iput-object p1, p0, Llyiahf/vczjk/f22;->OooO0O0:Llyiahf/vczjk/vb2;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/xa8;FLlyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 2

    new-instance v0, Llyiahf/vczjk/e22;

    const/4 v1, 0x0

    invoke-direct {v0, p2, p0, p1, v1}, Llyiahf/vczjk/e22;-><init>(FLlyiahf/vczjk/f22;Llyiahf/vczjk/v98;Llyiahf/vczjk/yo1;)V

    iget-object p1, p0, Llyiahf/vczjk/f22;->OooO0O0:Llyiahf/vczjk/vb2;

    invoke-static {p1, v0, p3}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
