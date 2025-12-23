.class public final Llyiahf/vczjk/ls4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/mb0;


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/ns4;

.field public final synthetic OooO0O0:Llyiahf/vczjk/hl7;

.field public final synthetic OooO0OO:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ns4;Llyiahf/vczjk/hl7;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ls4;->OooO00o:Llyiahf/vczjk/ns4;

    iput-object p2, p0, Llyiahf/vczjk/ls4;->OooO0O0:Llyiahf/vczjk/hl7;

    iput p3, p0, Llyiahf/vczjk/ls4;->OooO0OO:I

    return-void
.end method


# virtual methods
.method public final OooO00o()Z
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ls4;->OooO0O0:Llyiahf/vczjk/hl7;

    iget-object v0, v0, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/js4;

    iget-object v1, p0, Llyiahf/vczjk/ls4;->OooO00o:Llyiahf/vczjk/ns4;

    iget v2, p0, Llyiahf/vczjk/ls4;->OooO0OO:I

    invoke-virtual {v1, v0, v2}, Llyiahf/vczjk/ns4;->o00000OO(Llyiahf/vczjk/js4;I)Z

    move-result v0

    return v0
.end method
