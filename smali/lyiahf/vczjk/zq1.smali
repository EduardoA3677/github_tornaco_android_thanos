.class public final Llyiahf/vczjk/zq1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/hr1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hr1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/zq1;->this$0:Llyiahf/vczjk/hr1;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/an;

    iget-object v0, p0, Llyiahf/vczjk/zq1;->this$0:Llyiahf/vczjk/hr1;

    iget-object v1, v0, Llyiahf/vczjk/hr1;->OooOooo:Llyiahf/vczjk/lx4;

    iget-object p1, p1, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    iget-boolean v2, v0, Llyiahf/vczjk/hr1;->Oooo000:Z

    iget-boolean v3, v0, Llyiahf/vczjk/hr1;->Oooo00O:Z

    invoke-static {v0, v1, p1, v2, v3}, Llyiahf/vczjk/hr1;->o0000Ooo(Llyiahf/vczjk/hr1;Llyiahf/vczjk/lx4;Ljava/lang/String;ZZ)V

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1
.end method
