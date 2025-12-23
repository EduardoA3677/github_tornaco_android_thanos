.class public final synthetic Llyiahf/vczjk/fv0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOO0:Z

.field public final synthetic OooOOOO:Llyiahf/vczjk/hl5;

.field public final synthetic OooOOOo:Z

.field public final synthetic OooOOo:I

.field public final synthetic OooOOo0:Llyiahf/vczjk/cv0;


# direct methods
.method public synthetic constructor <init>(ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/cv0;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Llyiahf/vczjk/fv0;->OooOOO0:Z

    iput-object p2, p0, Llyiahf/vczjk/fv0;->OooOOO:Llyiahf/vczjk/oe3;

    iput-object p3, p0, Llyiahf/vczjk/fv0;->OooOOOO:Llyiahf/vczjk/hl5;

    iput-boolean p4, p0, Llyiahf/vczjk/fv0;->OooOOOo:Z

    iput-object p5, p0, Llyiahf/vczjk/fv0;->OooOOo0:Llyiahf/vczjk/cv0;

    iput p6, p0, Llyiahf/vczjk/fv0;->OooOOo:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/fv0;->OooOOo:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v6

    iget-boolean v3, p0, Llyiahf/vczjk/fv0;->OooOOOo:Z

    iget-object v4, p0, Llyiahf/vczjk/fv0;->OooOOo0:Llyiahf/vczjk/cv0;

    iget-boolean v0, p0, Llyiahf/vczjk/fv0;->OooOOO0:Z

    iget-object v1, p0, Llyiahf/vczjk/fv0;->OooOOO:Llyiahf/vczjk/oe3;

    iget-object v2, p0, Llyiahf/vczjk/fv0;->OooOOOO:Llyiahf/vczjk/hl5;

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/jv0;->OooO00o(ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/cv0;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
