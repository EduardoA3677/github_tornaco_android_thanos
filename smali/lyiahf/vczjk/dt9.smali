.class public final Llyiahf/vczjk/dt9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $onValueChange:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $value:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oe3;Z)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/dt9;->$onValueChange:Llyiahf/vczjk/oe3;

    iput-boolean p2, p0, Llyiahf/vczjk/dt9;->$value:Z

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/dt9;->$onValueChange:Llyiahf/vczjk/oe3;

    iget-boolean v1, p0, Llyiahf/vczjk/dt9;->$value:Z

    xor-int/lit8 v1, v1, 0x1

    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v1

    invoke-interface {v0, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
