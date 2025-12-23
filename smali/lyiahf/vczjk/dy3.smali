.class public final Llyiahf/vczjk/dy3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/p29;


# instance fields
.field public OooOOO:Ljava/lang/Object;

.field public OooOOO0:Ljava/lang/Object;

.field public final OooOOOO:Llyiahf/vczjk/n1a;

.field public final OooOOOo:Llyiahf/vczjk/qs5;

.field public OooOOo:Llyiahf/vczjk/fg9;

.field public OooOOo0:Llyiahf/vczjk/wl;

.field public OooOOoo:Z

.field public OooOo0:J

.field public OooOo00:Z

.field public final synthetic OooOo0O:Llyiahf/vczjk/jy3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jy3;Ljava/lang/Number;Ljava/lang/Number;Llyiahf/vczjk/n1a;Llyiahf/vczjk/cy3;)V
    .locals 6

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/dy3;->OooOo0O:Llyiahf/vczjk/jy3;

    iput-object p2, p0, Llyiahf/vczjk/dy3;->OooOOO0:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/dy3;->OooOOO:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/dy3;->OooOOOO:Llyiahf/vczjk/n1a;

    invoke-static {p2}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/dy3;->OooOOOo:Llyiahf/vczjk/qs5;

    iput-object p5, p0, Llyiahf/vczjk/dy3;->OooOOo0:Llyiahf/vczjk/wl;

    new-instance v0, Llyiahf/vczjk/fg9;

    iget-object v3, p0, Llyiahf/vczjk/dy3;->OooOOO0:Ljava/lang/Object;

    iget-object v4, p0, Llyiahf/vczjk/dy3;->OooOOO:Ljava/lang/Object;

    const/4 v5, 0x0

    move-object v2, p4

    move-object v1, p5

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/fg9;-><init>(Llyiahf/vczjk/wl;Llyiahf/vczjk/m1a;Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/dm;)V

    iput-object v0, p0, Llyiahf/vczjk/dy3;->OooOOo:Llyiahf/vczjk/fg9;

    return-void
.end method


# virtual methods
.method public final getValue()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/dy3;->OooOOOo:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method
