.class public final Llyiahf/vczjk/cr1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/hr1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hr1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/cr1;->this$0:Llyiahf/vczjk/hr1;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/cr1;->this$0:Llyiahf/vczjk/hr1;

    iget-object v1, v0, Llyiahf/vczjk/hr1;->OooOooo:Llyiahf/vczjk/lx4;

    iget-object v1, v1, Llyiahf/vczjk/lx4;->OooOo0o:Llyiahf/vczjk/jx4;

    iget-object v0, v0, Llyiahf/vczjk/hr1;->Oooo0O0:Llyiahf/vczjk/wv3;

    iget v0, v0, Llyiahf/vczjk/wv3;->OooO0o0:I

    new-instance v2, Llyiahf/vczjk/vv3;

    invoke-direct {v2, v0}, Llyiahf/vczjk/vv3;-><init>(I)V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/jx4;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object v0
.end method
