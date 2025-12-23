.class public final synthetic Llyiahf/vczjk/rh3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/h09;

.field public final synthetic OooOOO0:J

.field public final synthetic OooOOOO:Llyiahf/vczjk/hv3;

.field public final synthetic OooOOOo:Llyiahf/vczjk/h09;

.field public final synthetic OooOOo0:I


# direct methods
.method public synthetic constructor <init>(JLlyiahf/vczjk/h09;Llyiahf/vczjk/hv3;Llyiahf/vczjk/h09;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-wide p1, p0, Llyiahf/vczjk/rh3;->OooOOO0:J

    iput-object p3, p0, Llyiahf/vczjk/rh3;->OooOOO:Llyiahf/vczjk/h09;

    iput-object p4, p0, Llyiahf/vczjk/rh3;->OooOOOO:Llyiahf/vczjk/hv3;

    iput-object p5, p0, Llyiahf/vczjk/rh3;->OooOOOo:Llyiahf/vczjk/h09;

    iput p6, p0, Llyiahf/vczjk/rh3;->OooOOo0:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    iget p1, p0, Llyiahf/vczjk/rh3;->OooOOo0:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v6

    iget-wide v0, p0, Llyiahf/vczjk/rh3;->OooOOO0:J

    iget-object v2, p0, Llyiahf/vczjk/rh3;->OooOOO:Llyiahf/vczjk/h09;

    iget-object v3, p0, Llyiahf/vczjk/rh3;->OooOOOO:Llyiahf/vczjk/hv3;

    iget-object v4, p0, Llyiahf/vczjk/rh3;->OooOOOo:Llyiahf/vczjk/h09;

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/os9;->OooO(JLlyiahf/vczjk/h09;Llyiahf/vczjk/hv3;Llyiahf/vczjk/h09;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
